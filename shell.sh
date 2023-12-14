#!/bin/bash

FILENAME="./1131_dark_class"

echo "" > ${FILENAME}
make clean_all
make examples

echo "================ compile w/ optimization option -O2 ================" >> ${FILENAME}

for i in {7..11}
do
    echo "================ test n = $i ================"
    echo "================ test n = $i ================" >> ${FILENAME}
    echo "SETUP...."
    echo "SETUP...." >>  ${FILENAME}
    ./PC_Setup 512 $i >> ${FILENAME}
    echo >> ${FILENAME}
    echo "OPEN...."
    echo "OPEN...." >>  ${FILENAME}
    ./PC_PROVER_EVAL >> ${FILENAME}
    echo >>  ${FILENAME}
    echo "VERIFY...."
    echo "VERIFY...." >>  ${FILENAME}
    ./PC_VERIFIER_EVAL >> ${FILENAME}
    echo >>  ${FILENAME}
done
