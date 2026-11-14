import CLibXML2

public enum SignerCore {
    public static let version = "0.1.0"

    /// Compile-time libxml2 version number (proves CLibXML2 imports and links).
    public static var libxmlVersion: Int { Int(LIBXML_VERSION) }
}
