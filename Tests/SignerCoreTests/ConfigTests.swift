import XCTest
@testable import SignerCore

final class ConfigTests: XCTestCase {
    func testDefaults() {
        let c = AppConfig.default
        XCTAssertEqual(c.ports, [17165, 20806, 65097])
        XCTAssertEqual(c.originAllowlist, ["https://eporezi.purs.gov.rs"])
    }
}
