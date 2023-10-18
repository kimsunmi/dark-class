CC=gcc
CFLAGS := -g -lm -lcrypto -lgmp -lflint -lmpfr -lantic -fsanitize=address

SOURCE_DIR = source/
TEST_SOURCE_DIR = examples/

TEST_SETUP = PC_Setup
TEST_COMMIT = PC_Commit
TEST_PROVER_EVAL = PC_PROVER_EVAL
TEST_VERIFIER_EVAL = PC_VERIFIER_EVAL
TEST_poly = poly_test
all: 

poly: $(TEST_poly)

examples: $(TEST_SETUP) $(TEST_COMMIT) $(TEST_PROVER_EVAL) $(TEST_VERIFIER_EVAL)

clean:
	rm -f *.a *.o Txt/* $(TEST_SETUP) $(TEST_COMMIT) $(TEST_PROVER_EVAL) $(TEST_VERIFIER_EVAL)

clean_txt:
	rm -f *.a *.o Txt/* record/* 

clean_all:
	rm -f *.a *.o Txt/* record/* $(TEST_SETUP) $(TEST_COMMIT) $(TEST_PROVER_EVAL) $(TEST_VERIFIER_EVAL)
	

$(TEST_SETUP): $(TEST_SOURCE_DIR)setup_test.c 
	$(CC) -o $@ $(TEST_SOURCE_DIR)setup_test.c $(SOURCE_DIR)setup.c $(SOURCE_DIR)util.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)

$(TEST_COMMIT): $(TEST_SOURCE_DIR)commit_test.c 
	$(CC) -o $@ $(TEST_SOURCE_DIR)commit_test.c $(SOURCE_DIR)setup.c $(SOURCE_DIR)commit.c  $(SOURCE_DIR)util.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)

$(TEST_PROVER_EVAL): $(TEST_SOURCE_DIR)eval_prover_test.c 
	$(CC) -o $@  $(TEST_SOURCE_DIR)eval_prover_test.c $(SOURCE_DIR)setup.c $(SOURCE_DIR)commit.c $(SOURCE_DIR)evaluate.c $(SOURCE_DIR)util.c $(SOURCE_DIR)poe.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)

$(TEST_VERIFIER_EVAL): $(TEST_SOURCE_DIR)eval_verify_test.c 
	$(CC) -o $@ $(TEST_SOURCE_DIR)eval_verify_test.c $(SOURCE_DIR)setup.c $(SOURCE_DIR)commit.c $(SOURCE_DIR)evaluate.c $(SOURCE_DIR)util.c $(SOURCE_DIR)poe.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)

$(TEST_poly): $(TEST_SOURCE_DIR)poly_test.c 
	$(CC) -o $@ $(TEST_SOURCE_DIR)poly_test.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)
