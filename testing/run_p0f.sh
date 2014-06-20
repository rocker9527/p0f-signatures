#!/bin/bash
BPF_EXPR="tcp dst port 80"
echo "Generated BPF expression: $BPF_EXPR"
./p0f -s /var/run/p0f.sock -f ../p0f.fp -i lo -d "$BPF_EXPR" 