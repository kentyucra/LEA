#include <bits/stdc++.h>

using namespace std;

/*
– P : a 128-bit plaintext, consisting of four 32-bit words P = (P [0], P [1], P [2],
P [3])
– C: a 128-bit ciphertext, consisting of four 32-bit words C = (C[0], C[1], C[2],
C[3])
– X i : a 128-bit intermediate value (an input of i-th round in the encryption
function), consisting of four 32-bit words X i = (X i [0], X i [1], X i [2], X i [3])
– Len(x): the bit-length of a string x
– K: a master key. It is denoted as a concatenation of 32-bit words. K =
(K[0], K[1], K[2], K[3]) when Len(K) = 128; K = (K[0], K[1], ..., K[5]) when
Len(K) = 192; K = (K[0], K[1], ..., K[7]) when Len(K) = 256
– r: the number of rounds. r = 24 when Len(K) = 128; r = 28 when Len(K) =
192; r = 32 when Len(K) = 256
– RK: the concatenation of all round keys, defined by RK = (RK 0 , RK 1 ,
..., RK r−1 ) where RK i is the 192-bit round key for the i-th round. Each
RK i consists of six 32-bit words RK i = (RK i [0], RK i [1], ..., RK i [5])
– x ⊕ y: XOR (eXclusive OR) of bit strings x and y with same length
– x  y: Addition modulo 2 32 of 32-bit strings x and y
– ROL i (x): the i-bit left rotation on a 32-bit value x
– ROR i (x): the i-bit right rotation on a 32-bit value x
*/


/**BASIC OPERATIONS**/

void print_char(char a){
	for(int j = 7 ; j>=0;j--){
		if(a&(1<<j)){
			cout<<"1";
		}else{
			cout<<"0";
		}	
	}
	cout<<endl;
}

void print_int(unsigned int a){
	for(int j = 31 ; j>=0;j--){
		if(a&(1<<j)){
			cout<<"1";
		}else{
			cout<<"0";
		}	
	}
	cout<<endl;
}

#define INT_BITS 32

//Function to left rotate n by d bits(ROL_i)
unsigned int ROLi(unsigned int n, unsigned int i){
   return (n << i)|(n >> (INT_BITS - i));
}
 
//Function to right rotate n by d bits(ROR_i)
unsigned int RORi(unsigned int n, unsigned int i){
   return (n >> i)|(n << (INT_BITS - i));
}

unsigned int hexToUInt(string cad){
	stringstream converter(cad);
	unsigned int value;
	converter >> hex >> value;	
	return value;
}

//////////////////////7

struct P{
	//– P : a 128-bit plaintext, consisting of four 32-bit words P = (P[0], P[1], P[2], P[3]) 
	unsigned int P0;
	unsigned int P1;
	unsigned int P2;
	unsigned int P3;

	P(){}

	P(unsigned int _P0,unsigned int _P1,unsigned int _P2, unsigned int _P3){
		P0 = _P0;
		P1 = _P1;
		P2 = _P2;
		P3 = _P3;
	}

	void printP(){
		cout<<"P0: ";
		print_int(P0);

		cout<<"P1: ";
		print_int(P1);

		cout<<"P2: ";
		print_int(P2);

		cout<<"P3: ";
		print_int(P3);
	}

};


/*****KEY SCHEDULE***
Constants. The key schedule uses several constants for generating round keys,
which are defined as
δ[0] = 0xc3efe9db,
δ[1] = 0x44626b02,
δ[2] = 0x79e27c8a,
δ[3] = 0x78df30ec,
δ[4] = 0x715ea49e,
δ[5] = 0xc785da0a,
δ[6] = 0xe04ef22a,
δ[7] = 0xe5c40957.
****/

unsigned int delta[10];

void constantsLEA(){//TESTED
	delta[0] = strtol("c3efe9db", NULL, 16);
	delta[1] = strtol("44626b02", NULL, 16);
	delta[2] = strtol("79e27c8a", NULL, 16);
	delta[3] = strtol("78df30ec", NULL, 16);
	delta[4] = strtol("715ea49e", NULL, 16);
	delta[5] = strtol("c785da0a", NULL, 16);
	delta[6] = strtol("e04ef22a", NULL, 16);
	delta[7] = strtol("e5c40957", NULL, 16);
}

///--KEY SCHEDULE WITH A 128-bits KEY
void nextGenerationKeys128(unsigned int& T0, unsigned int& T1, unsigned int& T2, unsigned int& T3, unsigned int& roundNumber){

	T0 = ROLi( T0 + ROLi(delta[roundNumber%4], roundNumber), 1);
	T1 = ROLi( T1 + ROLi(delta[roundNumber%4], roundNumber+1), 3);
	T2 = ROLi( T2 + ROLi(delta[roundNumber%4], roundNumber+2), 6);
	T3 = ROLi( T3 + ROLi(delta[roundNumber%4], roundNumber+3), 11);

	roundNumber += 1;
}

///--KEY SCHEDULE WITH A 192-bits KEY
void nextGenerationKeys192(unsigned int& T0, unsigned int& T1, unsigned int& T2, unsigned int& T3, unsigned int& T4, unsigned int& T5, unsigned int& roundNumber){
	T0 = ROLi( T0 + ROLi(delta[roundNumber%6], roundNumber), 1);
	T1 = ROLi( T1 + ROLi(delta[roundNumber%6], roundNumber+1), 3);
	T2 = ROLi( T2 + ROLi(delta[roundNumber%6], roundNumber+2), 6);
	T3 = ROLi( T3 + ROLi(delta[roundNumber%6], roundNumber+3), 11);
	T4 = ROLi( T4 + ROLi(delta[roundNumber%6], roundNumber+4), 13);
	T5 = ROLi( T5 + ROLi(delta[roundNumber%6], roundNumber+5), 17);
}

///--KEY SCHEDULE WITH A 256-bits KEY
void nextGenerationKeys256(unsigned int& T0, unsigned int& T1, unsigned int& T2, unsigned int& T3, unsigned int& T4, unsigned int& T5, unsigned int& T6, unsigned int& T7, unsigned int& roundNumber){

	unsigned int T[10];
	T[0] = T0, T[1] = T1, T[2] = T2, T[3] = T3, T[4] = T4, T[5] = T5, T[6] = T6, T[7] = T7;

	T[(6*roundNumber) % 8] = ROLi( T[(6*roundNumber)%8] + ROLi(delta[roundNumber%8], roundNumber), 1);
	T[(6*roundNumber + 1) % 8] = ROLi( T[(6*roundNumber + 1) % 8] + ROLi(delta[roundNumber%8], roundNumber+1), 3);
	T[(6*roundNumber + 2) % 8] = ROLi( T[(6*roundNumber + 2) % 8] + ROLi(delta[roundNumber%8], roundNumber+2), 6);
	T[(6*roundNumber + 3) % 8] = ROLi( T[(6*roundNumber + 3) % 8] + ROLi(delta[roundNumber%8], roundNumber+3), 11);
	T[(6*roundNumber + 4) % 8] = ROLi( T[(6*roundNumber + 4) % 8] + ROLi(delta[roundNumber%8], roundNumber+4), 13);
	T[(6*roundNumber + 5) % 8] = ROLi( T[(6*roundNumber + 5) % 8] + ROLi(delta[roundNumber%8], roundNumber+5), 17);
	
	T0 = T[0], T1 = T[1], T2 = T[2], T3 = T[3], T4 = T[4], T5 = T[5], T6 = T[6], T7 = T[7];
}


vector<vector<unsigned int> > produceKeys128(vector<unsigned int> key){
	vector<vector<unsigned int> > RK;

	unsigned int T0 = key[0];
	unsigned int T1 = key[1];
	unsigned int T2 = key[2];
	unsigned int T3 = key[3];

	unsigned int roundNumber;

	for(roundNumber = 0 ; roundNumber < 24; ){

		nextGenerationKeys128(T0, T1, T2, T3, roundNumber);
		vector<unsigned int> RK_i;

		RK_i.push_back(T0);
		RK_i.push_back(T1);
		RK_i.push_back(T2);
		RK_i.push_back(T1);
		RK_i.push_back(T3);
		RK_i.push_back(T1);

		RK.push_back(RK_i);
	}

	return RK;
}

vector<vector<unsigned int> > produceKeys192(vector<unsigned int> key){
	vector<vector<unsigned int> > RK;

	unsigned int T0 = key[0];
	unsigned int T1 = key[1];
	unsigned int T2 = key[2];
	unsigned int T3 = key[3];
	unsigned int T4 = key[4];
	unsigned int T5 = key[5];

	unsigned int roundNumber;

	for(roundNumber = 0 ; roundNumber < 28; roundNumber++){

		nextGenerationKeys192(T0, T1, T2, T3, T4, T5, roundNumber);
		vector<unsigned int> RK_i;

		RK_i.push_back(T0);
		RK_i.push_back(T1);
		RK_i.push_back(T2);
		RK_i.push_back(T3);
		RK_i.push_back(T4);
		RK_i.push_back(T5);

		RK.push_back(RK_i);
	}
	return RK;
}

vector<vector<unsigned int> > produceKeys256(vector<unsigned int> key){
	vector<vector<unsigned int> > RK;

	unsigned int T0 = key[0];
	unsigned int T1 = key[1];
	unsigned int T2 = key[2];
	unsigned int T3 = key[3];
	unsigned int T4 = key[4];
	unsigned int T5 = key[5];
	unsigned int T6 = key[6];
	unsigned int T7 = key[7];

	unsigned int roundNumber;

	for(roundNumber = 0 ; roundNumber < 32; ){

		nextGenerationKeys256(T0, T1, T2, T3, T4, T5, T6, T7, roundNumber);

		unsigned int T[10];
		T[0] = T0, T[1] = T1, T[2] = T2, T[3] = T3, T[4] = T4, T[5] = T5, T[6] = T6, T[7] = T7;

		vector<unsigned int> RK_i;

		RK_i.push_back(T[(6*roundNumber) % 8]);
		RK_i.push_back(T[(6*roundNumber + 1) % 8]);
		RK_i.push_back(T[(6*roundNumber + 2) % 8]);
		RK_i.push_back(T[(6*roundNumber + 3) % 8]);
		RK_i.push_back(T[(6*roundNumber + 4) % 8]);
		RK_i.push_back(T[(6*roundNumber + 5) % 8]);

		RK.push_back(RK_i);

		roundNumber++;
	}
	return RK;
}


vector<vector<unsigned int> > RK11, RK22;

P LEAEncryptionAlgorithm(P pText, vector<unsigned int> key, unsigned int sizeKey){

	vector<vector<unsigned int> > RK;
	int r;

	switch(sizeKey){
		case 128:	
			RK = produceKeys128(key);
			r = 24;
			break;
		case 192:	
			RK = produceKeys192(key);
			r = 28;
			break;
		case 256:	
			RK = produceKeys256(key);
			r = 32;
			break;
		default:
			cout << "The sizeKey is INVALID!!" << endl;
			return P();
			break;
	}

	RK11 = RK;

	unsigned int RK0, RK1, RK2, RK3, RK4, RK5, P0, P1, P2, P3;

	unsigned int rNum;

	for( rNum = 0 ; rNum < r ; rNum++ ){
		RK0 = RK[rNum][0];
		RK1 = RK[rNum][1]; 
		RK2 = RK[rNum][2];
		RK3 = RK[rNum][3];
		RK4 = RK[rNum][4]; 
		RK5 = RK[rNum][5]; 

		P0 = pText.P0;
		P1 = pText.P1;
		P2 = pText.P2;
		P3 = pText.P3;

		pText.P0 = ROLi( (P0 ^ RK0) + (P1 ^ RK1), 9);
		pText.P1 = RORi( (P1 ^ RK2) + (P2 ^ RK3), 5);
		pText.P2 = RORi( (P2 ^ RK4) + (P3 ^ RK5), 3);
		pText.P3 = P0;

	}

	return pText;
}


P LEADecryptionAlgorithm(P eText, vector<unsigned int> key, unsigned int sizeKey){

	vector<vector<unsigned int> > RK;
	int r;

	switch(sizeKey){
		case 128:	
			RK = produceKeys128(key);
			r = 24;
			break;
		case 192:	
			RK = produceKeys192(key);
			r = 28;
			break;
		case 256:	
			RK = produceKeys256(key);
			r = 32;
			break;
		default:
			cout << "The sizeKey is INVALID!!" << endl;
			return P();
			break;
	}

	RK22 = RK;

	unsigned int RK0, RK1, RK2, RK3, RK4, RK5, P0, P1, P2, P3;

	int rNum;
	for( rNum = r-1 ; rNum >= 0  ; rNum-- ){

		RK0 = RK[rNum][0];
		RK1 = RK[rNum][1]; 
		RK2 = RK[rNum][2];
		RK3 = RK[rNum][3];
		RK4 = RK[rNum][4]; 
		RK5 = RK[rNum][5]; 

		P0 = eText.P0;
		P1 = eText.P1;
		P2 = eText.P2;
		P3 = eText.P3;

		eText.P1 = (RORi(P0, 9) - (P3 ^ RK0)) ^ RK1;
		eText.P2 = (ROLi(P1, 5) - (eText.P1 ^ RK2)) ^ RK3;
		eText.P3 = (ROLi(P2, 3) - (eText.P2 ^ RK4)) ^ RK5;
		eText.P0 = P3;	

	}

	return eText;
}

int main(){

	srand(time(NULL));
	
	constantsLEA();



	vector<unsigned int> key;

	key.push_back(rand());
	key.push_back(rand());
	key.push_back(rand());
	key.push_back(rand());
	key.push_back(rand());
	key.push_back(rand());
	key.push_back(rand());
	key.push_back(rand());

	//vector<vector<unsigned int> > keys = produceKeys128(key);
	
	P plaintext(rand(), rand(), rand(), rand());
	//P plaintext(rand(), rand(), rand(), rand());

	cout<<"plaintext = "<<endl;
	plaintext.printP();

	P ciphertext = LEAEncryptionAlgorithm(plaintext, key, 256);

	cout<<"ciphertext = "<<endl;
	ciphertext.printP();

	plaintext = LEADecryptionAlgorithm(ciphertext, key, 256);

	cout<<"plaintext = "<<endl;
	plaintext.printP();

	if(RK11 == RK22)
		cout<<"gg"<<endl;

	return 0;
}

	


/*
functions for read a message by character

int concatenation(char a, char b, char c, char d){
	//P[i] = a[4i + 3] || a[4i + 2] || a[4i + 1] || a[4i] for 0 ≤ i ≤ 3.

	int PBlock = 0;
	
	PBlock += a;
	PBlock <<= 8;
	
	PBlock += b;
	PBlock <<= 8;
	
	PBlock += c;
	PBlock <<= 8;
	
	PBlock += d;

	return PBlock;

}


char reverse(char a){
	char b = a; // reverse this (8-bit) byte
	b = (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
	return b;
}


P wordsToBlock(string block){

	int j = 0;

	P plaintext;
	plaintext.P0 = concatenation(reverse(block[4*j + 3]), reverse(block[4*j + 2]), reverse(block[4*j + 1]), reverse(block[4*j]));
	j++;
	plaintext.P1 = concatenation(reverse(block[4*j + 3]), reverse(block[4*j + 2]), reverse(block[4*j + 1]), reverse(block[4*j]));
	j++;
	plaintext.P2 = concatenation(reverse(block[4*j + 3]), reverse(block[4*j + 2]), reverse(block[4*j + 1]), reverse(block[4*j]));
	j++;
	plaintext.P3 = concatenation(reverse(block[4*j + 3]), reverse(block[4*j + 2]), reverse(block[4*j + 1]), reverse(block[4*j]));
	j++;

	return plaintext;

}


*/	
