
//
//  JailbreakDetector.swift
//  SecurityValidation
//
//  Multi-signal jailbreak detection for iOS.
//
//  Important:
//  - No client-side jailbreak detector is bypass-proof.
//  - A clean result means no configured indicator was detected.
//  - Keep enforcement decisions proportionate to the evidence.
//

import Foundation
import UIKit
import Darwin
import MachO


public enum SecurityEnvironment {
    case sandbox
    case production
}


// MARK: - Failure Reasons

public enum FailureReason: CustomStringConvertible, Equatable {
    case suspiciousFileExists(filePath: String)
    case suspiciousFileIsReadable(filePath: String)
    case appSandbox(filePath: String)
    case suspiciousURLScheme(url: String)
    case suspiciousSymlinkFound(path: String)
    case suspiciousDylibLoaded(dylibName: String)

    public var description: String {
        switch self {
        case .suspiciousFileExists(let path):
            return "Suspicious file or directory exists: \(path)"

        case .suspiciousFileIsReadable(let path):
            return "Suspicious file or directory is readable: \(path)"

        case .appSandbox(let path):
            return "Write outside the app sandbox succeeded: \(path)"

        case .suspiciousURLScheme(let scheme):
            return "Suspicious URL scheme is available: \(scheme)"

        case .suspiciousSymlinkFound(let path):
            return "Suspicious symbolic link found: \(path)"

        case .suspiciousDylibLoaded(let name):
            return "Suspicious dynamic library loaded: \(name)"
        }
    }
}

// MARK: - Result

public enum Result: Equatable {
    case pass
    case fail(reasons: [FailureReason])
    case simulator
    case macCatalyst
}



// MARK: - Detector
public struct JailbreakDetector {

    // MARK: - Public API

    @MainActor
    public static func runAllChecks(
        environment: SecurityEnvironment
    ) -> Result {

        #if targetEnvironment(simulator)
        return .simulator
        #elseif targetEnvironment(macCatalyst)
        return .macCatalyst
        #else

        var reasons: [FailureReason] = []

        // Checks common to both environments
        reasons += isContainsSuspiciousApps()
        reasons += isSuspiciousSystemPathsExists()
        reasons += hasSuspiciousSymlinks()
        reasons += checkDYLD()

        // URL scheme checks
        reasons += checkSuspiciousURLs()

        // Environment-specific checks
        switch environment {
        case .sandbox:
            // Do not attempt an outside-container write.
            break

        case .production:
            reasons += checkOutsideSandboxWrite()
        }

        var uniqueReasons: [FailureReason] = []

        for reason in reasons where !uniqueReasons.contains(reason) {
            uniqueReasons.append(reason)
        }

        return uniqueReasons.isEmpty
            ? .pass
            : .fail(reasons: uniqueReasons)

        #endif
    }

    /// Backward-compatible entry point.
    @MainActor
    public static func runAllChecks() -> Result {
        runAllChecks(environment: .production)
    }

    // Keep your existing check implementations here:
    // isContainsSuspiciousApps()
    // isSuspiciousSystemPathsExists()
    // checkSuspiciousURLs()
    // checkOutsideSandboxWrite()
    // hasSuspiciousSymlinks()
    // checkDYLD()
}
