# ``SecurityValidation``



## Step 1: Configure Target App Info.plist

For the URL Scheme validation step (checkURLSchemes) to register correctly in modern iOS versions, the host application integrating your framework must declare those schemes in its own Info.plist file.
Add the following dictionary key configuration to the target application's configuration array:
xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
</array>
Use code with caution.

## Step 2: Integrate and Call Your Framework

1. Build the framework project (Command + B).
2. Drag the output .framework binary into the Frameworks, Libraries, and Embedded Content section of your target client app's build settings.
3. Ensure its embedding status dropdown is marked as Embed & Sign.
4. Consume the custom framework cleanly inside your client code.


import UIKit
import SecurityValidation 

Task { @MainActor in
    let result = JailBrokenHelper.runAllChecks()

  switch result {
    case .pass:
        print("Security validation passed")

  case .fail(let reasons):
        for reason in reasons {
            print(reason.description)
        }

  case .simulator:
        print("Running on Simulator")

  case .macCatalyst:
        print("Running on Mac Catalyst")
    }
}
