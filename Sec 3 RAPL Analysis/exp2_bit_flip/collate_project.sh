#!/bin/bash
echo "--- PROJECT DUMP START ---" > project_dump.txt

echo "== 1. FILE LIST ==" >> project_dump.txt
ls -R | grep -v "mbedtls_SGX-2.6.0" >> project_dump.txt

echo -e "\n== 2. Enclave.edl ==" >> project_dump.txt
cat Enclave.edl >> project_dump.txt

echo -e "\n== 3. Enclave.c ==" >> project_dump.txt
cat Enclave.c >> project_dump.txt

echo -e "\n== 4. App.cpp ==" >> project_dump.txt
cat App.cpp >> project_dump.txt

echo -e "\n== 5. Makefile ==" >> project_dump.txt
cat Makefile >> project_dump.txt

echo -e "\n== 6. key.h structure (Byte counts) ==" >> project_dump.txt
grep "len =" key.h >> project_dump.txt

echo -e "\n== 7. key.h actual data ==" >> project_dump.txt
cat key.h >> project_dump.txt

echo "--- PROJECT DUMP END ---" >> project_dump.txt
echo "Dump created in project_dump.txt"
