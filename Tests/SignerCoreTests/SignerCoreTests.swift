import XCTest
@testable import SignerCore

final class SignerCoreTests: XCTestCase {
    func testScaffold() {
        XCTAssertEqual(SignerCore.version, "0.1.0")
        XCTAssertGreaterThan(SignerCore.libxmlVersion, 20000)
    }
}
