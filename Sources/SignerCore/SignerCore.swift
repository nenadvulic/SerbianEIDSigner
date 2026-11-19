import CLibXML2

public enum SignerCore {
    public static let version = "0.1.0"

    public static var libxmlVersion: Int { Int(LIBXML_VERSION) }
}
