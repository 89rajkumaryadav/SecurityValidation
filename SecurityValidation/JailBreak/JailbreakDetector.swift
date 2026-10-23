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

// MARK: - Security Environment

public enum SecurityEnvironment {
    /// Runs detection without attempting an outside-sandbox write.
    case sandbox

    /// Runs all configured checks, including the sandbox boundary probe.
    case production
}

// MARK: - Failure Reason

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
            return "Suspicious file or directory exists: \(filePath)"

        case .suspiciousFileIsReadable(let filePath):
            return "Suspicious file or directory is readable: \(filePath)"

        case .appSandbox(let filePath):
            return "Write outside the app sandbox succeeded: \(filePath)"

        case .suspiciousURLScheme(let url):
            return "Suspicious URL scheme is available: \(url)"

        case .suspiciousSymlinkFound(let path):
            return "Suspicious symbolic link detected: \(path)"

        case .suspiciousDylibLoaded(let dylibName):
            return "Suspicious dynamic library loaded: \(dylibName)"
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

// MARK: - Jailbreak Detector

public struct JailbreakDetector {

    // MARK: Public API

    /// Runs jailbreak checks according to the selected environment.
    ///
    /// - Parameter environment:
    ///   `.sandbox` skips the outside-sandbox write probe.
    ///   `.production` enables every configured check.
    ///
    /// - Returns: The consolidated detection result.
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

        // Checks enabled in both environments.
        reasons += isContainsSuspiciousApps()
        reasons += isSuspiciousSystemPathsExists()
        reasons += checkSuspiciousURLs()
        reasons += hasSuspiciousSymlinks()
        reasons += checkDYLD()

        // Environment-specific checks.
        switch environment {
        case .sandbox:
            // Skip the outside-sandbox write probe.
            break

        case .production:
            reasons += checkOutsideSandboxWrite()
        }

        // Deduplicate findings while preserving their order.
        var uniqueReasons: [FailureReason] = []

        for reason in reasons {
            if !uniqueReasons.contains(reason) {
                uniqueReasons.append(reason)
            }
        }

        return uniqueReasons.isEmpty
            ? .pass
            : .fail(reasons: uniqueReasons)

        #endif
    }

    /// Backward-compatible API. Defaults to production checks.
    @MainActor
    public static func runAllChecks() -> Result {
        runAllChecks(environment: .production)
    }

    // MARK: Application Checks

    public static func isContainsSuspiciousApps() -> [FailureReason] {
        checkPaths(suspiciousAppsPathToCheck)
    }

    // MARK: System Path Checks

    public static func isSuspiciousSystemPathsExists() -> [FailureReason] {
        checkPaths(suspiciousSystemPathsToCheck)
    }

    private static func checkPaths(
        _ paths: [String]
    ) -> [FailureReason] {

        var reasons: [FailureReason] = []
        let fileManager = FileManager.default

        for path in paths {
            guard fileManager.fileExists(atPath: path) else {
                continue
            }

            reasons.append(
                .suspiciousFileExists(filePath: path)
            )

            if fileManager.isReadableFile(atPath: path) {
                reasons.append(
                    .suspiciousFileIsReadable(filePath: path)
                )
            }
        }

        return reasons
    }

    // MARK: URL Scheme Checks

    @MainActor
    private static func checkSuspiciousURLs() -> [FailureReason] {

        let schemes = [
            "cydia",
            "sileo",
            "zbra"
        ]

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

    // MARK: Sandbox Boundary Check

    /// Attempts to create a unique file outside the app container.
    ///
    /// A successful creation is evidence that the expected boundary
    /// was crossed. The file is removed after the test.
    private static func checkOutsideSandboxWrite() -> [FailureReason] {

        let path = "/private/jbcheck-\(UUID().uuidString)"

        let descriptor = path.withCString { filePath in
            Darwin.open(
                filePath,
                O_WRONLY | O_CREAT | O_EXCL,
                mode_t(S_IRUSR | S_IWUSR)
            )
        }

        guard descriptor >= 0 else {
            // A failed attempt is inconclusive: it does not prove
            // that all sandbox restrictions are functioning correctly.
            return []
        }

        defer {
            _ = Darwin.close(descriptor)

            _ = path.withCString { filePath in
                Darwin.unlink(filePath)
            }
        }

        return [
            .appSandbox(filePath: path)
        ]
    }

    // MARK: Symbolic Link Checks

    private static func hasSuspiciousSymlinks() -> [FailureReason] {

        let paths = [
            "/var/jb",
            "/var/binpack",
            "/var/jb/basebin",
            "/var/jb/usr",
            "/var/jb/Library",
            "/var/jb/etc",
            "/var/jb/preboot",
            "/var/containers/Bundle/tweaksupport"
        ]

        var reasons: [FailureReason] = []
        let fileManager = FileManager.default

        for path in paths {
            do {
                _ = try fileManager.destinationOfSymbolicLink(
                    atPath: path
                )

                reasons.append(
                    .suspiciousSymlinkFound(path: path)
                )
            } catch {
                // Absence of a confirmed symlink is not proof
                // that the device is uncompromised.
                continue
            }
        }

        return reasons
    }

    // MARK: Dynamic Library Checks

    private static func checkDYLD() -> [FailureReason] {

        let suspiciousLibraries: Set<String> = [
            "SubstrateLoader.dylib",
            "MobileSubstrate.dylib",
            "libsubstrate.dylib",
            "libhooker.dylib",
            "SubstrateBootstrap.dylib",
            "libsubstitute.dylib",
            "libellekit.dylib",
            "ElleKit.dylib",
            "TweakInject.dylib",
            "FridaGadget.dylib",
            "frida-agent.dylib",
            "SSLKillSwitch2.dylib"
        ]

        var reasons: [FailureReason] = []
        let imageCount = _dyld_image_count()

        for index in 0..<imageCount {
            guard let imagePointer = _dyld_get_image_name(index) else {
                continue
            }

            let loadedPath = String(cString: imagePointer)

            let loadedName = URL(
                fileURLWithPath: loadedPath
            ).lastPathComponent

            if suspiciousLibraries.contains(loadedName) {
                reasons.append(
                    .suspiciousDylibLoaded(
                        dylibName: loadedName
                    )
                )
            }

            // Rootless jailbreak paths are supporting indicators.
            let normalizedPath = loadedPath.lowercased()

            if normalizedPath.hasPrefix("/var/jb/") ||
                normalizedPath.contains(
                    "/mobile substrate/dynamiclibraries/"
                ) {

                reasons.append(
                    .suspiciousDylibLoaded(
                        dylibName: loadedPath
                    )
                )
            }
        }

        return reasons
    }

    // MARK: Suspicious Application Paths

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
            "/Applications/checkra1n.app",

            // Package managers and modern jailbreaks
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/Palera1n.app",
            "/Applications/TrollStore.app",

            // Rootless jailbreak locations
            "/var/jb/Applications/Cydia.app",
            "/var/jb/Applications/Sileo.app",
            "/var/jb/Applications/Zebra.app"
        ]
    }

    // MARK: Suspicious System Paths

    public static var suspiciousSystemPathsToCheck: [String] {
        [
            // Traditional jailbreak artifacts
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
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

            // Rootless jailbreak artifacts
            "/var/jb",
            "/var/binpack",
            "/var/containers/Bundle/tweaksupport",
            "/var/mobile/Library/palera1n",
            "/var/mobile/Library/xyz.willy.Zebra",
            "/var/lib/undecimus",
            "/var/jb/basebin",
            "/var/jb/usr",
            "/var/jb/etc",
            "/var/jb/Library",
            "/var/jb/.installed_palera1n",
            "/var/binpack/Applications",
            "/var/binpack/usr",

            // Bootstrap and TrollStore-related paths
            "/var/containers/Bundle/Application/trollstorehelper",
            "/var/containers/Bundle/trollstore",
            "/var/jb/preboot",
            "/var/jb/var"
        ]
    }
}
