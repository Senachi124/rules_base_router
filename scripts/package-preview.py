"""Resolve generated Info.plists for the ad-hoc development preview only."""
import pathlib
import plistlib
import sys

app = pathlib.Path(sys.argv[1])
targets = [
    ("App", "RouteBar", "com.routebar.app", app),
]
for source, module, identifier, bundle in targets:
    replacements = {
        "$(EXECUTABLE_NAME)": module, "$(PRODUCT_NAME)": module,
        "$(PRODUCT_MODULE_NAME)": module, "$(PRODUCT_BUNDLE_IDENTIFIER)": identifier,
        "$(DEVELOPMENT_LANGUAGE)": "en", "$(MARKETING_VERSION)": "0.1.0",
        "$(CURRENT_PROJECT_VERSION)": "1", "$(MACOSX_DEPLOYMENT_TARGET)": "13.0",
        "$(AppIdentifierPrefix)": "", "$(TeamIdentifierPrefix)": "",
    }
    def resolve(value):
        if isinstance(value, str):
            for token, replacement in replacements.items():
                value = value.replace(token, replacement)
            return value
        if isinstance(value, dict):
            return {key: resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [resolve(item) for item in value]
        return value
    with open(f"macos/{source}/Info.plist", "rb") as handle:
        info = resolve(plistlib.load(handle))
    info["RouteBarBuildChannel"] = "DevelopmentPreview"
    info["RouteBarBackend"] = "RustV2"
    info["CFBundleShortVersionString"] = "0.2.0"
    info["CFBundleVersion"] = "1"
    with (bundle / "Contents/Info.plist").open("wb") as handle:
        plistlib.dump(info, handle)
