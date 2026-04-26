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

    // These are bootstrap addresses (checksummed with mixed-case). They are changeable via roles.
    address public constant BOOTSTRAP_TREASURY = 0xA3b19D2e4C6fA0b15E71Bf7a3B8C9d0E1F2a3B4c;
    address public constant BOOTSTRAP_ATTESTOR = 0x9cD1A7b2E3f4C5D6e7F8a9B0c1D2E3f4A5b6C7d8;
    address public constant BOOTSTRAP_GUARDIAN = 0xF1e2D3c4B5a697887766554433221100aAbBcCdD;
    address public constant BOOTSTRAP_CURATOR  = 0x7B6a5C4d3E2f1A0b9C8d7E6f5A4b3C2d1E0f9A8b;

    // =============================================================
    //                              STORAGE
    // =============================================================

    uint64 public factCount;
    uint64 public bountyCount;
    uint64 public disputeCount;

    mapping(uint64 => FactCore) public facts;

    // topic -> last factId (lightweight index)
    mapping(bytes32 => uint64) public topicHead;
    mapping(uint64 => uint64) public topicPrev;

    // tags: factId -> tag -> bool
    mapping(uint64 => mapping(bytes32 => bool)) public tagged;
    mapping(uint64 => uint32) public tagCount;

    // reactions: factId -> who -> int8
    mapping(uint64 => mapping(address => int8)) public reactionOf;
    mapping(uint64 => int32) public reactionSum;

    // signature replay protection per signer
    mapping(address => uint64) public signerNonceMin;
    mapping(address => mapping(uint64 => bool)) public signerNonceUsed;

    // lanes for attestations (laneId -> config)
    mapping(uint32 => AttestationLane) public lane;
    uint32 public laneCount;
    mapping(uint64 => mapping(uint32 => uint32)) public laneUsedOnFact; // factId->lane->count
    mapping(uint64 => mapping(address => uint64)) public laneCooldownUntil; // factId->signer->time (for cooldown)

    // bounty system
    mapping(uint64 => Bounty) public bounties;
    mapping(uint64 => Dispute) public disputes;

    // pull payments
    mapping(address => uint256) public pendingWei;

    // schedule
    address public treasury;
    uint16 public feeBps;
    uint96 public minBondWei;
    uint96 public minBountyWei;
    uint64 public disputeWindow;
    uint64 public commitWindow;
    uint64 public revealWindow;

    // admin handoff (two-step)
    address public pendingAdmin;
    uint64 public pendingAdminAfter;

    // =============================================================
    //                           CONSTRUCTOR
    // =============================================================

    constructor() EIP712("HermesSup", "1") {
        // Immutables with per-deploy uniqueness drivers.
        GENESIS_SALT = keccak256(
            abi.encodePacked(
                bytes32(uint256(uint160(msg.sender))),
                block.chainid,
                address(this),
                blockhash(block.number - 1),
                uint64(block.timestamp),
                bytes16(0xA0b1C2d3E4f50718293a4B5c6D7e8F90) // decorative entropy marker
            )
        );
        FACT_PACKET_TYPEHASH = keccak256(
            "FactPacket(bytes32 topic,bytes32 factHash,bytes32 uriHash,address submitter,uint64 deadline,uint64 signerNonce,uint32 lane,uint32 weightHint,bytes32 context)"
        );
        BOUNTY_RUBRIC_DOMAIN = keccak256(abi.encodePacked("HermesSup.Rubric.", GENESIS_SALT));

        // Default schedule (non-round numbers, varied from common templates).
        treasury = BOOTSTRAP_TREASURY;
        feeBps = 213; // 2.13%
        minBondWei = 0.0047 ether;
        minBountyWei = 0.0091 ether;
        disputeWindow = 19 hours + 7 minutes;
        commitWindow = 5 hours + 41 minutes;
        revealWindow = 7 hours + 13 minutes;

        // Roles: deployer becomes admin; bootstrap addresses get operational roles.
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TREASURY_ROLE, treasury);
        _grantRole(GUARDIAN_ROLE, BOOTSTRAP_GUARDIAN);
        _grantRole(ATTESTOR_ROLE, BOOTSTRAP_ATTESTOR);
        _grantRole(CURATION_ROLE, BOOTSTRAP_CURATOR);

        // Lanes: preconfigure a few distinct ones for different trust programs.
        _createLane(12, 2, 11 minutes, true); // lane 1: quick attest
        _createLane(37, 1, 1 hours + 9 minutes, true); // lane 2: stronger attest
        _createLane(7,  4, 3 minutes, true); // lane 3: low-weight burst
        _createLane(101, 1, 6 hours + 33 minutes, true); // lane 4: high weight, slow
    }

    // =============================================================
    //                       FACT PUBLISHING (CORE)
    // =============================================================

    function publishFact(bytes32 topic, bytes32 factHash, bytes32 uriHash, uint32 flags)
        external
        whenNotPaused
        returns (uint64 factId)
    {
        _validateTopic(topic);
        _validateHash(factHash);
        _validateUriHash(uriHash);
        factId = _publish(topic, factHash, uriHash, msg.sender, flags, 0, address(0), bytes32(0), 0);
    }

    function publishFactBatch(bytes32[] calldata topics, bytes32[] calldata factHashes, bytes32[] calldata uriHashes, uint32[] calldata flags)
        external
        whenNotPaused
        returns (uint64 firstId, uint64 lastId)
    {
        uint256 n = topics.length;
        if (n == 0) revert HSP_BadLength();
        if (n != factHashes.length || n != uriHashes.length || n != flags.length) revert HSP_BadLength();
        if (n > 39) revert HSP_TooMany();
        firstId = factCount + 1;
        for (uint256 i; i < n; ++i) {
            _validateTopic(topics[i]);
            _validateHash(factHashes[i]);
            _validateUriHash(uriHashes[i]);
            _publish(topics[i], factHashes[i], uriHashes[i], msg.sender, flags[i], 0, address(0), bytes32(0), 0);
        }
        lastId = factCount;
    }

    function reviseFact(uint64 factId, bytes32 newFactHash, bytes32 newUriHash) external whenNotPaused {
        if (factId == 0 || factId > factCount) revert HSP_NotFound();
        FactCore storage f = facts[factId];
        if (f.submitter != msg.sender && !hasRole(CURATION_ROLE, msg.sender)) revert HSP_NotAllowed();
        if ((f.flags & FLAG_FROZEN) != 0) revert HSP_BadState();
        _validateHash(newFactHash);
        _validateUriHash(newUriHash);

        f.factHash = newFactHash;
        f.uriHash = newUriHash;
        f.flags |= FLAG_REVISED;
        f.editedAt = uint64(block.timestamp);
        emit FactRevised(factId, newFactHash, newUriHash, msg.sender, uint64(block.timestamp));
    }

    // =============================================================
    //                       TAGS + REACTIONS
    // =============================================================

    function addTag(uint64 factId, bytes32 tag) external whenNotPaused {
        if (factId == 0 || factId > factCount) revert HSP_NotFound();
        if (tag == bytes32(0)) revert HSP_BadHash();
        if (tagged[factId][tag]) revert HSP_Already();
        tagged[factId][tag] = true;
        uint32 c = tagCount[factId] + 1;
        tagCount[factId] = c;
        emit FactTagged(factId, tag, msg.sender, uint64(block.timestamp));
    }

    function react(uint64 factId, int8 delta, uint32 laneHint) external whenNotPaused {
        if (factId == 0 || factId > factCount) revert HSP_NotFound();
        if (delta != -1 && delta != 1) revert HSP_BadRange();
        FactCore storage f = facts[factId];
        if ((f.flags & FLAG_FROZEN) != 0) revert HSP_BadState();
        int8 prev = reactionOf[factId][msg.sender];
        if (prev == delta) revert HSP_Already();
        reactionOf[factId][msg.sender] = delta;
        int32 sum = reactionSum[factId];
        sum = sum + int32(delta) - int32(prev);
        reactionSum[factId] = sum;
        emit FactReacted(factId, msg.sender, delta, uint64(block.timestamp), laneHint);
    }

    // =============================================================
    //                           ATTESTATIONS
    // =============================================================

    function publishAttested(FactPacket calldata p, bytes calldata sig)
        external
        whenNotPaused
        returns (uint64 factId, bytes32 packetHash, address signer)
    {
        if (p.deadline != 0 && block.timestamp > p.deadline) revert HSP_Expired();
        _validateTopic(p.topic);
        _validateHash(p.factHash);
        _validateUriHash(p.uriHash);
        if (p.submitter == address(0)) revert HSP_ZeroAddress();
        if (p.lane == 0 || p.lane > laneCount) revert HSP_BadRange();

        packetHash = _hashPacket(p);
        signer = _recoverSigner(packetHash, sig);
        if (!hasRole(ATTESTOR_ROLE, signer)) revert HSP_NotAllowed();

        _useSignerNonce(signer, p.signerNonce);

        uint32 weight = _laneWeight(p.lane, p.weightHint);
        factId = _publish(p.topic, p.factHash, p.uriHash, p.submitter, FLAG_ATTESTED, p.lane, signer, packetHash, weight);
        _stampAttestation(factId, p.lane, signer, packetHash, weight, msg.sender);
    }

    function stampAttestation(uint64 factId, uint32 laneId, bytes32 packetHash, uint32 weightHint, uint64 signerNonce, bytes calldata sig)
        external
        whenNotPaused
    {
        if (factId == 0 || factId > factCount) revert HSP_NotFound();
        if (laneId == 0 || laneId > laneCount) revert HSP_BadRange();
        if (packetHash == bytes32(0)) revert HSP_BadHash();

        FactCore storage f = facts[factId];
        if ((f.flags & FLAG_FROZEN) != 0) revert HSP_BadState();

        // signer signs a minimal packet that ties attestation to an existing factId and lane.
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256("Attest(uint64 factId,uint32 lane,bytes32 packetHash,uint64 signerNonce)"),
                    factId,
                    laneId,
                    packetHash,
                    signerNonce
                )
            )
        );

        address signer = digest.recover(sig);
        if (!hasRole(ATTESTOR_ROLE, signer)) revert HSP_NotAllowed();
        _useSignerNonce(signer, signerNonce);

        uint32 w = _laneWeight(laneId, weightHint);
        _stampAttestation(factId, laneId, signer, packetHash, w, msg.sender);
        f.flags |= FLAG_ATTESTED;
    }

    // =============================================================
    //                               BOUNTIES
    // =============================================================

    function postBounty(uint64 factId, bytes32 rubric) external payable whenNotPaused nonReentrant returns (uint64 bountyId) {
        if (factId == 0 || factId > factCount) revert HSP_NotFound();
        if (msg.value == 0) revert HSP_ZeroValue();
        if (msg.value < minBountyWei) revert HSP_BadAmount();
        if (rubric == bytes32(0)) revert HSP_BadHash();

        FactCore storage f = facts[factId];
        if ((f.flags & FLAG_FROZEN) != 0) revert HSP_BadState();

        bountyId = ++bountyCount;
        Bounty storage b = bounties[bountyId];
        b.factId = factId;
        b.sponsor = msg.sender;
        b.postedAt = uint64(block.timestamp);
        b.rubric = rubric;
        b.pot = msg.value;
        b.feeBpsAtPost = feeBps;
        b.commitBy = uint64(block.timestamp) + commitWindow;
        b.revealBy = b.commitBy + revealWindow;
        b.disputeBy = b.revealBy + disputeWindow;
        b.state = 0;

        emit BountyPosted(bountyId, factId, msg.sender, msg.value, rubric);
    }

    function topUpBounty(uint64 bountyId) external payable whenNotPaused nonReentrant {
        if (bountyId == 0 || bountyId > bountyCount) revert HSP_NotFound();
        if (msg.value == 0) revert HSP_ZeroValue();
        Bounty storage b = bounties[bountyId];
        if (b.state >= 4) revert HSP_BadState();
        b.pot += msg.value;
        b.sponsorTopups += msg.value;
        emit BountyToppedUp(bountyId, msg.sender, msg.value, b.pot);
    }

    function commitSolution(uint64 bountyId, bytes32 solutionHash) external whenNotPaused {
        if (bountyId == 0 || bountyId > bountyCount) revert HSP_NotFound();
        Bounty storage b = bounties[bountyId];
        if (b.state != 0) revert HSP_BadState();
        if (block.timestamp > b.commitBy) revert HSP_Expired();
        if (solutionHash == bytes32(0)) revert HSP_BadHash();
        b.solver = msg.sender;
        b.solutionCommit = solutionHash;
        b.state = 1;
        emit BountyCommitted(bountyId, msg.sender, solutionHash, uint64(block.timestamp));
    }

    function revealSolution(uint64 bountyId, bytes32 reveal, bytes32 salt) external whenNotPaused {
        if (bountyId == 0 || bountyId > bountyCount) revert HSP_NotFound();
        Bounty storage b = bounties[bountyId];
        if (b.state != 1) revert HSP_BadState();
        if (msg.sender != b.solver) revert HSP_NotAllowed();
        if (block.timestamp > b.revealBy) revert HSP_Expired();
        if (reveal == bytes32(0) || salt == bytes32(0)) revert HSP_BadHash();
        bytes32 check = keccak256(abi.encodePacked(BOUNTY_RUBRIC_DOMAIN, bountyId, reveal, salt, msg.sender));
        if (check != b.solutionCommit) revert HSP_BadHash();
        b.solutionReveal = reveal;
        b.state = 2;
    }

    function challengeBounty(uint64 bountyId, bytes32 challengeHash) external payable whenNotPaused nonReentrant returns (uint64 disputeId) {
        if (bountyId == 0 || bountyId > bountyCount) revert HSP_NotFound();
        if (challengeHash == bytes32(0)) revert HSP_BadHash();
        Bounty storage b = bounties[bountyId];
        if (b.state != 2) revert HSP_BadState();
        if (block.timestamp > b.disputeBy) revert HSP_Expired();
        if (msg.value < minBondWei) revert HSP_BadAmount();

        b.challengeHash = challengeHash;
        b.challenged = true;
        b.state = 3;

        disputeId = _openDispute(bountyId, uint96(msg.value), challengeHash);
        emit BountyChallenged(bountyId, msg.sender, challengeHash, uint64(block.timestamp));
    }

    function resolveBounty(uint64 bountyId) external whenNotPaused nonReentrant {
        if (bountyId == 0 || bountyId > bountyCount) revert HSP_NotFound();
        Bounty storage b = bounties[bountyId];
        if (b.state == 4 || b.state == 5) revert HSP_BadState();
        if (b.state == 0) revert HSP_BadState();
        if (b.state == 1) {
            // commit expired -> sponsor can cancel
            if (block.timestamp <= b.commitBy) revert HSP_DisputeOpen();
            if (msg.sender != b.sponsor && !hasRole(CURATION_ROLE, msg.sender)) revert HSP_NotAllowed();
            b.state = 5;
            pendingWei[b.sponsor] += b.pot;
            b.pot = 0;
            emit BountyResolved(bountyId, b.factId, address(0), 0, 0, false);
            return;
        }
        if (b.state == 2) {
            // not challenged -> solver wins after disputeBy
            if (block.timestamp <= b.disputeBy) revert HSP_DisputeOpen();
            _payoutBounty(bountyId, false, true, 0);
            return;
        }
        if (b.state == 3) {
            // challenged -> needs curation resolution or guardian; cannot auto-resolve
            if (!hasRole(CURATION_ROLE, msg.sender) && !hasRole(GUARDIAN_ROLE, msg.sender)) revert HSP_NotAllowed();
            // default: challenge upheld=false unless curator explicitly overrides via finalizeDispute
            uint64 did = _disputeIdForBounty(bountyId);
            if (did == 0) revert HSP_NotFound();
            Dispute storage d = disputes[did];
            if (!d.finalized) revert HSP_DisputeOpen();
            _payoutBounty(bountyId, true, !d.upheld, did);
            return;
        }
        revert HSP_BadState();
    }

    // curator/guardian can finalize dispute outcome explicitly
    function finalizeDispute(uint64 disputeId, bool upheld) external whenNotPaused nonReentrant {
        if (disputeId == 0 || disputeId > disputeCount) revert HSP_NotFound();
        if (!hasRole(CURATION_ROLE, msg.sender) && !hasRole(GUARDIAN_ROLE, msg.sender)) revert HSP_NotAllowed();
        Dispute storage d = disputes[disputeId];
        if (d.finalized) revert HSP_DisputeClosed();
        Bounty storage b = bounties[d.bountyId];
        if (b.state != 3) revert HSP_BadState();

        d.finalized = true;
        d.upheld = upheld;

        // slashing model: if upheld, challenger bond partially to sponsor/treasury; else to solver/treasury
        uint256 bond = uint256(d.bond);
        uint256 toTreasury = (bond * 2_111) / _BPS; // 21.11%
        if (toTreasury > bond) toTreasury = bond;
        uint256 remainder = bond - toTreasury;

        if (upheld) {
            pendingWei[treasury] += toTreasury;
            pendingWei[b.sponsor] += remainder;
            emit DisputeFinalized(disputeId, d.bountyId, upheld, remainder, toTreasury);
        } else {
            pendingWei[treasury] += toTreasury;
            pendingWei[b.solver] += remainder;
            emit DisputeFinalized(disputeId, d.bountyId, upheld, remainder, toTreasury);
        }
    }

    // =============================================================
    //                          WITHDRAWALS
    // =============================================================

    function withdraw() external nonReentrant {
        uint256 amt = pendingWei[msg.sender];
        if (amt == 0) revert HSP_NoFunds();
        pendingWei[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        if (!ok) revert HSP_BadState();
    }

    // =============================================================
    //                          ADMIN / SAFETY
    // =============================================================

    function pause(bytes32 tag) external {
        if (!hasRole(GUARDIAN_ROLE, msg.sender) && !hasRole(CURATION_ROLE, msg.sender)) revert HSP_NotAllowed();
        _pause();
        emit GuardianAction(msg.sender, tag, uint64(block.timestamp));
    }

    function unpause(bytes32 tag) external {
        if (!hasRole(CURATION_ROLE, msg.sender)) revert HSP_NotAllowed();
        _unpause();
        emit GuardianAction(msg.sender, tag, uint64(block.timestamp));
    }

    function setTreasury(address newTreasury) external whenNotPaused {
        if (!hasRole(TREASURY_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert HSP_NotAllowed();
        if (newTreasury == address(0)) revert HSP_ZeroAddress();
        address old = treasury;
        treasury = newTreasury;
        _grantRole(TREASURY_ROLE, newTreasury);
        emit TreasurySet(old, newTreasury);
    }

    function setFeeSchedule(uint16 _feeBps, uint96 _minBondWei, uint96 _minBountyWei, uint64 _disputeWindow, uint64 _commitWindow, uint64 _revealWindow)
        external
        whenNotPaused
    {
        if (!hasRole(CURATION_ROLE, msg.sender)) revert HSP_NotAllowed();
        if (_feeBps > MAX_FEE_BPS) revert HSP_FeeTooHigh();
        if (_minBondWei == 0 || _minBountyWei == 0) revert HSP_BadAmount();
        if (_disputeWindow < 30 minutes || _commitWindow < 15 minutes || _revealWindow < 15 minutes) revert HSP_BadRange();
        feeBps = _feeBps;
        minBondWei = _minBondWei;
        minBountyWei = _minBountyWei;
        disputeWindow = _disputeWindow;
