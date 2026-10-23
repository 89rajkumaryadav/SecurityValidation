//
//  JailbreakDetector.swift
//  SecurityValidation
//
//  Created by Rajkumar Yadav on 22/10/26.
//

import Foundation
import UIKit
import Darwin
import MachO

// MARK: - Failure Reason Enum

public enum FailureReason: CustomStringConvertible, Equatable {
    case suspiciousFileExists(filePath: String)
    case suspiciousFileIsReadable(filePath: String)
    case appSandbox(filePath: String)
    case suspiciousURLScheme(url: String)
    case suspiciousSymlinkFound(path: String)
    case suspiciousDylibLoaded(dylibName: String)

    public var description: String {
        switch self {
        case .suspiciousFileExists(let filePath):
            return "Detected suspicious file at \(filePath)"

        case .suspiciousFileIsReadable(let filePath):
            return "Suspicious file can be opened at \(filePath)"

        case .appSandbox(let filePath):
            return "Able to write outside sandbox to \(filePath)"

        case .suspiciousURLScheme(let url):
            return "Can open suspicious URL scheme \(url)"

        case .suspiciousSymlinkFound(let path):
            return "Suspicious symbolic link detected at \(path)"

        case .suspiciousDylibLoaded(let dylibName):
            return "Suspicious dynamic library loaded: \(dylibName)"
        }
    }
}

// MARK: - Result Enum

public enum Result: Equatable {
    case pass
    case fail(reasons: [FailureReason])
    case simulator
    case macCatalyst
}


public struct JailbreakDetector {

    // MARK: - Public API

    /// Run all checks and return a unified result.
    @MainActor
    public static func runAllChecks() -> Result {

        #if targetEnvironment(simulator)
        return .simulator
        #elseif targetEnvironment(macCatalyst)
        return .macCatalyst
        #else

        var reasons: [FailureReason] = []

        reasons += isContainsSuspiciousApps()
        reasons += isSuspiciousSystemPathsExists()
        reasons += checkSuspiciousURLs()
        reasons += checkOutsideSandboxWrite()
        reasons += hasSuspiciousSymlinks()
        reasons += checkDYLD()

        return reasons.isEmpty ? .pass : .fail(reasons: reasons)

        #endif
    }

    // MARK: - Direct Checks

    public static func isContainsSuspiciousApps() -> [FailureReason] {
        return checkPaths(suspiciousAppsPathToCheck)
    }

    public static func isSuspiciousSystemPathsExists() -> [FailureReason] {
        return checkPaths(suspiciousSystemPathsToCheck)
    }

    private static func checkPaths(_ paths: [String]) -> [FailureReason] {
        var reasons: [FailureReason] = []
        let fileManager = FileManager.default

        for path in paths {
            guard fileManager.fileExists(atPath: path) else {
                continue
            }

            reasons.append(.suspiciousFileExists(filePath: path))

            if fileManager.isReadableFile(atPath: path) {
                reasons.append(.suspiciousFileIsReadable(filePath: path))
            }
        }

        return reasons
    }

    @MainActor
    private static func checkSuspiciousURLs() -> [FailureReason] {
        let schemes = ["cydia", "sileo", "zbra"]
        var reasons: [FailureReason] = []

        for scheme in schemes {
            guard let url = URL(string: "\(scheme)://") else {
                continue
            }

            if UIApplication.shared.canOpenURL(url) {
                reasons.append(
                    .suspiciousURLScheme(url: scheme)
                )
            }
        }

        return reasons
    }

    // MARK: - Sandbox Check

    private static func checkOutsideSandboxWrite() -> [FailureReason] {
        let fileManager = FileManager.default
        let fileName = "security_validation_\(UUID().uuidString)"
        let path = "/private/\(fileName)"

        do {
            try "sandbox_test".write(
                toFile: path,
                atomically: true,
                encoding: .utf8
            )

            // Remove the test file even if a later operation fails.
            defer {
                try? fileManager.removeItem(atPath: path)
            }

            return [.appSandbox(filePath: path)]

        } catch {
            return []
        }
    }

    // MARK: - Symbolic Link Check

    private static func hasSuspiciousSymlinks() -> [FailureReason] {
        // Avoid ordinary system paths such as /var that may
        // legitimately be symbolic links on iOS.
        let paths = [
            "/var/jb",
            "/var/binpack",
            "/var/jb/basebin",
            "/var/jb/usr"
        ]

        var reasons: [FailureReason] = []

        for path in paths {
            do {
                _ = try FileManager.default.destinationOfSymbolicLink(
                    atPath: path
                )

                reasons.append(.suspiciousSymlinkFound(path: path))
            } catch {
                // The path is not a symbolic link, or cannot be inspected.
                continue
            }
        }

        return reasons
    }

    // MARK: - Dynamic Library Check

    private static func checkDYLD() -> [FailureReason] {
        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "libhooker.dylib",
            "SubstrateBootstrap.dylib",
            "libsubstitute.dylib",
            "libellekit.dylib"
        ]

        var reasons: [FailureReason] = []
        let imageCount = _dyld_image_count()

        for index in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(index) else {
                continue
            }

            let loadedPath = String(cString: imageName)
            let loadedName = URL(fileURLWithPath: loadedPath).lastPathComponent

            for library in suspiciousLibraries {
                if loadedName == library {
                    reasons.append(
                        .suspiciousDylibLoaded(dylibName: loadedName)
                    )
                }
            }
        }

        return reasons
    }

    // MARK: - Suspicious Application Paths

    public static var suspiciousAppsPathToCheck: [String] {
        [
            // Traditional jailbreaks
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",

            // Modern jailbreaks
            "/Applications/Palera1n.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/TrollStore.app",
            "/var/containers/Bundle/Application/TrollStore.app",

            // Checkra1n
            "/Applications/checkra1n.app",

            // Rootless jailbreaks
            "/var/jb/Applications/Cydia.app",
            "/var/jb/Applications/Sileo.app",
            "/var/jb/Applications/Zebra.app"
        ]
    }

    // MARK: - Suspicious System Paths

    public static var suspiciousSystemPathsToCheck: [String] {
        [
            // Traditional paths
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/bin/bash",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",

            // Modern jailbreak paths
            "/var/jb",
            "/var/binpack",
            "/var/containers/Bundle/tweaksupport",
            "/var/mobile/Library/palera1n",
            "/var/mobile/Library/xyz.willy.Zebra",
            "/var/lib/undecimus",

            // Palera1n
            "/var/jb/basebin",
            "/var/jb/usr",
            "/var/jb/etc",
            "/var/jb/Library",
            "/var/jb/.installed_palera1n",
            "/var/binpack/Applications",
            "/var/binpack/usr",

            // TrollStore
            "/var/containers/Bundle/Application/trollstorehelper",
            "/var/containers/Bundle/trollstore",

            // Bootstrap files
            "/var/jb/preboot",
            "/var/jb/var"
        ]
    }
}
