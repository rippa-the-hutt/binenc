P=binenc
PD=debug
S=assembly
T=test
EXT_SOURCES= RippaSSL/Cipher.cpp RippaSSL/Mac.cpp RippaSSL/Base.cpp binIO.cpp
EXT_OBJECTS= Cipher.o Mac.o Base.o binIO.o
SOURCES=main.cpp $(EXT_SOURCES)
OBJECTS=main.o $(EXT_OBJECTS)
T_SOURCES=tests.cpp $(EXT_SOURCES)
T_OBJECTS=tests.o $(EXT_OBJECTS)
DFLAGS= -ggdb -O0 -std=c++17
CFLAGS= -Wall -Os -std=c++17
LDLIBS= -lssl -lcrypto
CC=g++

$(P): $(P).o
	$(CC) -o $(P) $(OBJECTS) $(LDLIBS)

$(P).o: $(SOURCES)
	$(CC) $(CFLAGS) -c $(SOURCES)

$(PD): $(PD).o
	$(CC) -o $(PD) $(OBJECTS) $(LDLIBS)

$(PD).o: $(SOURCES)
	$(CC) $(DFLAGS) -c $(SOURCES)

$(T): $(T).o
	$(CC) -o $(T) $(T_OBJECTS) $(LDLIBS)

$(T).o: $(T_SOURCES)
	$(CC) $(DFLAGS) -c $(T_SOURCES)

$(S): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) -fverbose-asm -S $(SOURCES)

clean:
	rm *.o *.exe $(P) $(PD)
