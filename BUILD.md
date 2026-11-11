# Digest tool - build and run instructions

The quarterly register fingerprint must be produced by the bundled digest
utility. Build it with the documented settings so the executable recorded in
the bundle is reproducible:

    gcc -O2 -s -o digest_tool tools/digest_tool.c
    ./digest_tool registers/supplier_register_2026q3.csv

The utility prints one line per supplier:

    <supplier_id> <risk_score> <record_fingerprint_hex>

After the supplier rows it prints:

    register_fingerprint <hex>
    count <n>

Record the SHA-256 of the built executable in the bundle attestation. The build
must use exactly the `-O2 -s` settings shown above; do not edit the checked-in
source before building.
