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
