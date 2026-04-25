// HermesSup: a public facts rail with attestations, bounties, and dispute windows.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title HermesSup
 * @notice A facts-sharing program: users publish compact "fact capsules" (hash + topic + uriHash),
 *         while attestors sign EIP-712 packets for higher-trust feeds. Native-value bounties can be
 *         posted on factIds and resolved via a dispute window.
 *
 *         This contract is designed for EVM mainnets:
 *         - role-based permissions (OpenZeppelin AccessControl)
 *         - nonReentrant for value-moving functions
 *         - pausability for incident response
 *         - pull-based withdrawals for awards and fees
 *         - signature replay protection (per-signer nonce)
 *
 *         The chain stores commitments; the "truth" interface can fetch expanded text offchain by URI.
 */
contract HermesSup is AccessControl, Pausable, ReentrancyGuard, EIP712 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // =============================================================
    //                              ROLES
    // =============================================================

    bytes32 public constant CURATION_ROLE = keccak256("HermesSup.CURATION_ROLE.1d9e0f0a");
    bytes32 public constant ATTESTOR_ROLE = keccak256("HermesSup.ATTESTOR_ROLE.8bdf7d2c");
    bytes32 public constant GUARDIAN_ROLE = keccak256("HermesSup.GUARDIAN_ROLE.7a3f12e1");
    bytes32 public constant TREASURY_ROLE = keccak256("HermesSup.TREASURY_ROLE.9c66b2d4");

    // =============================================================
    //                           CUSTOM ERRORS
    // =============================================================

    error HSP_ZeroValue();
    error HSP_ZeroAddress();
    error HSP_BadRange();
    error HSP_BadState();
    error HSP_NotAllowed();
    error HSP_Expired();
    error HSP_BadSig();
    error HSP_Already();
    error HSP_NotFound();
    error HSP_TooMany();
    error HSP_BadTopic();
    error HSP_BadHash();
    error HSP_BadAmount();
    error HSP_DisputeOpen();
    error HSP_DisputeClosed();
    error HSP_NoFunds();
    error HSP_FeeTooHigh();
    error HSP_BadNonce();
    error HSP_BadLength();

    // =============================================================
    //                              EVENTS
    // =============================================================

    event FactPublished(
        uint64 indexed factId,
        bytes32 indexed topic,
        bytes32 indexed factHash,
        address submitter,
        uint64 publishedAt,
        uint32 flags,
        bytes32 uriHash
    );

    event FactRevised(
        uint64 indexed factId,
        bytes32 newFactHash,
        bytes32 newUriHash,
        address indexed editor,
        uint64 editedAt
    );

    event FactTagged(uint64 indexed factId, bytes32 indexed tag, address indexed who, uint64 at);
    event FactReacted(uint64 indexed factId, address indexed who, int8 delta, uint64 at, uint32 lane);

    event AttestationStamped(
        uint64 indexed factId,
        address indexed attestOrRelay,
        address indexed signer,
        bytes32 packetHash,
        uint64 at,
        uint32 weight
    );

    event BountyPosted(uint64 indexed bountyId, uint64 indexed factId, address indexed sponsor, uint256 amount, bytes32 rubric);
    event BountyToppedUp(uint64 indexed bountyId, address indexed sponsor, uint256 amount, uint256 newTotal);
    event BountyCommitted(uint64 indexed bountyId, address indexed solver, bytes32 solutionHash, uint64 at);
    event BountyChallenged(uint64 indexed bountyId, address indexed challenger, bytes32 challengeHash, uint64 at);
    event BountyResolved(uint64 indexed bountyId, uint64 indexed factId, address indexed winner, uint256 paid, uint256 fee, bool challenged);

    event DisputeOpened(uint64 indexed disputeId, uint64 indexed bountyId, address indexed opener, uint96 bond, bytes32 challengeHash, uint64 at);
    event DisputeFinalized(uint64 indexed disputeId, uint64 indexed bountyId, bool upheld, uint256 slashToWinner, uint256 slashToTreasury);

    event TreasurySet(address indexed oldTreasury, address indexed newTreasury);
    event FeeScheduleSet(uint16 feeBps, uint96 minBondWei, uint96 minBountyWei, uint64 disputeWindow, uint64 commitWindow, uint64 revealWindow);
    event GuardianAction(address indexed guardian, bytes32 indexed tag, uint64 at);
    event AdminHandoffProposed(address indexed from, address indexed to, uint64 effectiveAfter);
    event AdminHandoffAccepted(address indexed newAdmin);

    // =============================================================
    //                              TYPES
    // =============================================================

    struct FactCore {
        bytes32 topic;
        bytes32 factHash;
        bytes32 uriHash;
        address submitter;
        uint64 publishedAt;
        uint64 editedAt;
        uint32 flags;
        uint32 attestationScore;
    }

    struct AttestationLane {
        uint32 weight;
        uint32 maxPerFact;
        uint64 cooldown;
        bool enabled;
    }

    struct FactPacket {
        bytes32 topic;
        bytes32 factHash;
        bytes32 uriHash;
        address submitter;
        uint64 deadline;
        uint64 signerNonce;
        uint32 lane;
        uint32 weightHint;
        bytes32 context;
    }

    struct Bounty {
        uint64 factId;
        address sponsor;
        address solver;
        uint64 postedAt;
        uint64 commitBy;
        uint64 revealBy;
        uint64 disputeBy;
        bytes32 rubric;
        bytes32 solutionCommit;
        bytes32 solutionReveal;
        bytes32 challengeHash;
        uint256 pot;
        uint256 sponsorTopups;
        uint96 bond;
        uint16 feeBpsAtPost;
        uint8 state; // 0=open,1=committed,2=revealed,3=challenged,4=resolved,5=cancelled
        bool challenged;
    }

    struct Dispute {
        uint64 bountyId;
        address opener;
        uint64 openedAt;
        uint96 bond;
        bytes32 challengeHash;
        bool finalized;
        bool upheld;
    }

    // =============================================================
    //                           CONSTANTS / IMMUTABLES
    // =============================================================

    uint256 private constant _BPS = 10_000;
    uint16 public constant MAX_FEE_BPS = 1_250; // 12.5%

    uint32 public constant FLAG_ATTESTED = 1 << 0;
    uint32 public constant FLAG_REVISED = 1 << 1;
    uint32 public constant FLAG_FLAGGED = 1 << 2;
    uint32 public constant FLAG_FROZEN = 1 << 3;

    bytes32 public immutable GENESIS_SALT;
    bytes32 public immutable FACT_PACKET_TYPEHASH;
    bytes32 public immutable BOUNTY_RUBRIC_DOMAIN;

