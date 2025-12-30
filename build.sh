#!/bin/bash

# Gmail Guard Build Script
# Creates installable WoltLab Suite package

echo "=== Gmail Guard Plugin Builder ==="
echo ""

# Check if we're in the right directory
if [ ! -f "package.xml" ]; then
    echo "Error: package.xml not found. Please run this script from the plugin directory."
    exit 1
fi

PACKAGE_NAME="com.example.gmailguard"
OUTPUT_FILE="${PACKAGE_NAME}.tar.gz"

echo "Building package: ${PACKAGE_NAME}"
echo "Output file: ${OUTPUT_FILE}"
echo ""

# Remove old package if exists
if [ -f "$OUTPUT_FILE" ]; then
    echo "Removing old package..."
    rm "$OUTPUT_FILE"
fi

# Create list of files to include
FILES_TO_INCLUDE=(
    "package.xml"
    "eventListener.xml"
    "option.xml"
    "install.sql"
    "files/"
    "language/"
)

echo "Including files:"
for file in "${FILES_TO_INCLUDE[@]}"; do
    if [ -e "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file (not found)"
    fi
done
echo ""

# Create the package
echo "Creating package..."
tar -czf "$OUTPUT_FILE" \
    --exclude='.DS_Store' \
    --exclude='*.sh' \
    --exclude='README.md' \
    --exclude='*.tar.gz' \
    "${FILES_TO_INCLUDE[@]}"

if [ $? -eq 0 ]; then
    SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
    echo ""
    echo "✓ Package created successfully!"
    echo "  File: $OUTPUT_FILE"
    echo "  Size: $SIZE"
    echo ""
    echo "Next steps:"
    echo "1. Upload this package in WoltLab ACP → Pakete → Paket installieren"
    echo "2. Get a free API key from https://emailrep.io"
    echo "3. Configure the plugin in ACP → Optionen → Benutzer → Registrierung → Gmail Guard"
else
    echo ""
    echo "✗ Error creating package!"
    exit 1
fi
