import java.io.File;
import java.io.*;

class AES {
	byte [][] st = new byte[4][4];
	byte [][] expandedKey = new byte[4][44];
	byte[] S =	{ 
		(byte) 0x63,	(byte) 0x7c,	(byte) 0x77,	(byte) 0x7b,	(byte) 0xf2, 
		(byte) 0x6b,	(byte) 0x6f,	(byte) 0xc5,	(byte) 0x30,	(byte) 0x1, 
		(byte) 0x67,	(byte) 0x2b,	(byte) 0xfe,	(byte) 0xd7,	(byte) 0xab, 
		(byte) 0x76,	(byte) 0xca,	(byte) 0x82,	(byte) 0xc9,	(byte) 0x7d, 
		(byte) 0xfa,	(byte) 0x59,	(byte) 0x47,	(byte) 0xf0,	(byte) 0xad, 
		(byte) 0xd4,	(byte) 0xa2,	(byte) 0xaf,	(byte) 0x9c,	(byte) 0xa4, 
		(byte) 0x72,	(byte) 0xc0,	(byte) 0xb7,	(byte) 0xfd,	(byte) 0x93, 
		(byte) 0x26,	(byte) 0x36,	(byte) 0x3f,	(byte) 0xf7,	(byte) 0xcc, 
		(byte) 0x34,	(byte) 0xa5,	(byte) 0xe5,	(byte) 0xf1,	(byte) 0x71, 
		(byte) 0xd8,	(byte) 0x31,	(byte) 0x15,	(byte) 0x4,	(byte) 0xc7, 
		(byte) 0x23,	(byte) 0xc3,	(byte) 0x18,	(byte) 0x96,	(byte) 0x5, 
		(byte) 0x9a,	(byte) 0x7,	(byte) 0x12,	(byte) 0x80,	(byte) 0xe2, 
		(byte) 0xeb,	(byte) 0x27,	(byte) 0xb2,	(byte) 0x75,	(byte) 0x9, 
		(byte) 0x83,	(byte) 0x2c,	(byte) 0x1a,	(byte) 0x1b,	(byte) 0x6e, 
		(byte) 0x5a,	(byte) 0xa0,	(byte) 0x52,	(byte) 0x3b,	(byte) 0xd6, 
		(byte) 0xb3,	(byte) 0x29,	(byte) 0xe3,	(byte) 0x2f,	(byte) 0x84, 
		(byte) 0x53,	(byte) 0xd1,	(byte) 0x0,	(byte) 0xed,	(byte) 0x20, 
		(byte) 0xfc,	(byte) 0xb1,	(byte) 0x5b,	(byte) 0x6a,	(byte) 0xcb, 
		(byte) 0xbe,	(byte) 0x39,	(byte) 0x4a,	(byte) 0x4c,	(byte) 0x58, 
		(byte) 0xcf,	(byte) 0xd0,	(byte) 0xef,	(byte) 0xaa,	(byte) 0xfb, 
		(byte) 0x43,	(byte) 0x4d,	(byte) 0x33,	(byte) 0x85,	(byte) 0x45, 
		(byte) 0xf9,	(byte) 0x2,	(byte) 0x7f,	(byte) 0x50,	(byte) 0x3c, 
		(byte) 0x9f,	(byte) 0xa8,	(byte) 0x51,	(byte) 0xa3,	(byte) 0x40, 
		(byte) 0x8f,	(byte) 0x92,	(byte) 0x9d,	(byte) 0x38,	(byte) 0xf5, 
		(byte) 0xbc,	(byte) 0xb6,	(byte) 0xda,	(byte) 0x21,	(byte) 0x10, 
		(byte) 0xff,	(byte) 0xf3,	(byte) 0xd2,	(byte) 0xcd,	(byte) 0xc, 
		(byte) 0x13,	(byte) 0xec,	(byte) 0x5f,	(byte) 0x97,	(byte) 0x44, 
		(byte) 0x17,	(byte) 0xc4,	(byte) 0xa7,	(byte) 0x7e,	(byte) 0x3d, 
		(byte) 0x64,	(byte) 0x5d,	(byte) 0x19,	(byte) 0x73,	(byte) 0x60, 
		(byte) 0x81,	(byte) 0x4f,	(byte) 0xdc,	(byte) 0x22,	(byte) 0x2a, 
		(byte) 0x90,	(byte) 0x88,	(byte) 0x46,	(byte) 0xee,	(byte) 0xb8, 
		(byte) 0x14,	(byte) 0xde,	(byte) 0x5e,	(byte) 0xb,	(byte) 0xdb, 
		(byte) 0xe0,	(byte) 0x32,	(byte) 0x3a,	(byte) 0xa,	(byte) 0x49, 
		(byte) 0x6,	(byte) 0x24,	(byte) 0x5c,	(byte) 0xc2,	(byte) 0xd3, 
		(byte) 0xac,	(byte) 0x62,	(byte) 0x91,	(byte) 0x95,	(byte) 0xe4, 
		(byte) 0x79,	(byte) 0xe7,	(byte) 0xc8,	(byte) 0x37,	(byte) 0x6d, 
		(byte) 0x8d,	(byte) 0xd5,	(byte) 0x4e,	(byte) 0xa9,	(byte) 0x6c, 
		(byte) 0x56,	(byte) 0xf4,	(byte) 0xea,	(byte) 0x65,	(byte) 0x7a, 
		(byte) 0xae,	(byte) 0x8,	(byte) 0xba,	(byte) 0x78,	(byte) 0x25, 
		(byte) 0x2e,	(byte) 0x1c,	(byte) 0xa6,	(byte) 0xb4,	(byte) 0xc6, 
		(byte) 0xe8,	(byte) 0xdd,	(byte) 0x74,	(byte) 0x1f,	(byte) 0x4b, 
		(byte) 0xbd,	(byte) 0x8b,	(byte) 0x8a,	(byte) 0x70,	(byte) 0x3e, 
		(byte) 0xb5,	(byte) 0x66,	(byte) 0x48,	(byte) 0x3,	(byte) 0xf6, 
		(byte) 0xe,	(byte) 0x61,	(byte) 0x35,	(byte) 0x57,	(byte) 0xb9, 
		(byte) 0x86,	(byte) 0xc1,	(byte) 0x1d,	(byte) 0x9e,	(byte) 0xe1, 
		(byte) 0xf8,	(byte) 0x98,	(byte) 0x11,	(byte) 0x69,	(byte) 0xd9, 
		(byte) 0x8e,	(byte) 0x94,	(byte) 0x9b,	(byte) 0x1e,	(byte) 0x87, 
		(byte) 0xe9,	(byte) 0xce,	(byte) 0x55,	(byte) 0x28,	(byte) 0xdf, 
		(byte) 0x8c,	(byte) 0xa1,	(byte) 0x89,	(byte) 0xd,	(byte) 0xbf, 
		(byte) 0xe6,	(byte) 0x42,	(byte) 0x68,	(byte) 0x41,	(byte) 0x99, 
		(byte) 0x2d,	(byte) 0xf,	(byte) 0xb0,	(byte) 0x54,	(byte) 0xbb, 
		(byte) 0x16 };
	
	byte[] Si = { 
		(byte) 0x52,	(byte) 0x9,	(byte) 0x6a,	(byte) 0xd5,	(byte) 0x30, 
		(byte) 0x36,	(byte) 0xa5,	(byte) 0x38,	(byte) 0xbf,	(byte) 0x40, 
		(byte) 0xa3,	(byte) 0x9e,	(byte) 0x81,	(byte) 0xf3,	(byte) 0xd7, 
		(byte) 0xfb,	(byte) 0x7c,	(byte) 0xe3,	(byte) 0x39,	(byte) 0x82, 
		(byte) 0x9b,	(byte) 0x2f,	(byte) 0xff,	(byte) 0x87,	(byte) 0x34, 
		(byte) 0x8e,	(byte) 0x43,	(byte) 0x44,	(byte) 0xc4,	(byte) 0xde, 
		(byte) 0xe9,	(byte) 0xcb,	(byte) 0x54,	(byte) 0x7b,	(byte) 0x94, 
		(byte) 0x32,	(byte) 0xa6,	(byte) 0xc2,	(byte) 0x23,	(byte) 0x3d, 
		(byte) 0xee,	(byte) 0x4c,	(byte) 0x95,	(byte) 0xb,	(byte) 0x42, 
		(byte) 0xfa,	(byte) 0xc3,	(byte) 0x4e,	(byte) 0x8,	(byte) 0x2e, 
		(byte) 0xa1,	(byte) 0x66,	(byte) 0x28,	(byte) 0xd9,	(byte) 0x24, 
		(byte) 0xb2,	(byte) 0x76,	(byte) 0x5b,	(byte) 0xa2,	(byte) 0x49, 
		(byte) 0x6d,	(byte) 0x8b,	(byte) 0xd1,	(byte) 0x25,	(byte) 0x72, 
		(byte) 0xf8,	(byte) 0xf6,	(byte) 0x64,	(byte) 0x86,	(byte) 0x68, 
		(byte) 0x98,	(byte) 0x16,	(byte) 0xd4,	(byte) 0xa4,	(byte) 0x5c, 
		(byte) 0xcc,	(byte) 0x5d,	(byte) 0x65,	(byte) 0xb6,	(byte) 0x92, 
		(byte) 0x6c,	(byte) 0x70,	(byte) 0x48,	(byte) 0x50,	(byte) 0xfd, 
		(byte) 0xed,	(byte) 0xb9,	(byte) 0xda,	(byte) 0x5e,	(byte) 0x15, 
		(byte) 0x46,	(byte) 0x57,	(byte) 0xa7,	(byte) 0x8d,	(byte) 0x9d, 
		(byte) 0x84,	(byte) 0x90,	(byte) 0xd8,	(byte) 0xab,	(byte) 0x0, 
		(byte) 0x8c,	(byte) 0xbc,	(byte) 0xd3,	(byte) 0xa,	(byte) 0xf7, 
		(byte) 0xe4,	(byte) 0x58,	(byte) 0x5,	(byte) 0xb8,	(byte) 0xb3, 
		(byte) 0x45,	(byte) 0x6,	(byte) 0xd0,	(byte) 0x2c,	(byte) 0x1e, 
		(byte) 0x8f,	(byte) 0xca,	(byte) 0x3f,	(byte) 0xf,	(byte) 0x2, 
		(byte) 0xc1,	(byte) 0xaf,	(byte) 0xbd,	(byte) 0x3,	(byte) 0x1, 
		(byte) 0x13,	(byte) 0x8a,	(byte) 0x6b,	(byte) 0x3a,	(byte) 0x91, 
		(byte) 0x11,	(byte) 0x41,	(byte) 0x4f,	(byte) 0x67,	(byte) 0xdc, 
		(byte) 0xea,	(byte) 0x97,	(byte) 0xf2,	(byte) 0xcf,	(byte) 0xce, 
		(byte) 0xf0,	(byte) 0xb4,	(byte) 0xe6,	(byte) 0x73,	(byte) 0x96, 
		(byte) 0xac,	(byte) 0x74,	(byte) 0x22,	(byte) 0xe7,	(byte) 0xad, 
		(byte) 0x35,	(byte) 0x85,	(byte) 0xe2,	(byte) 0xf9,	(byte) 0x37, 
		(byte) 0xe8,	(byte) 0x1c,	(byte) 0x75,	(byte) 0xdf,	(byte) 0x6e, 
		(byte) 0x47,	(byte) 0xf1,	(byte) 0x1a,	(byte) 0x71,	(byte) 0x1d, 
		(byte) 0x29,	(byte) 0xc5,	(byte) 0x89,	(byte) 0x6f,	(byte) 0xb7, 
		(byte) 0x62,	(byte) 0xe,	(byte) 0xaa,	(byte) 0x18,	(byte) 0xbe, 
		(byte) 0x1b,	(byte) 0xfc,	(byte) 0x56,	(byte) 0x3e,	(byte) 0x4b, 
		(byte) 0xc6,	(byte) 0xd2,	(byte) 0x79,	(byte) 0x20,	(byte) 0x9a, 
		(byte) 0xdb,	(byte) 0xc0,	(byte) 0xfe,	(byte) 0x78,	(byte) 0xcd, 
		(byte) 0x5a,	(byte) 0xf4,	(byte) 0x1f,	(byte) 0xdd,	(byte) 0xa8, 
		(byte) 0x33,	(byte) 0x88,	(byte) 0x7,	(byte) 0xc7,	(byte) 0x31, 
		(byte) 0xb1,	(byte) 0x12,	(byte) 0x10,	(byte) 0x59,	(byte) 0x27, 
		(byte) 0x80,	(byte) 0xec,	(byte) 0x5f,	(byte) 0x60,	(byte) 0x51, 
		(byte) 0x7f,	(byte) 0xa9,	(byte) 0x19,	(byte) 0xb5,	(byte) 0x4a, 
		(byte) 0xd,	(byte) 0x2d,	(byte) 0xe5,	(byte) 0x7a,	(byte) 0x9f, 
		(byte) 0x93,	(byte) 0xc9,	(byte) 0x9c,	(byte) 0xef,	(byte) 0xa0, 
		(byte) 0xe0,	(byte) 0x3b,	(byte) 0x4d,	(byte) 0xae,	(byte) 0x2a, 
		(byte) 0xf5,	(byte) 0xb0,	(byte) 0xc8,	(byte) 0xeb,	(byte) 0xbb, 
		(byte) 0x3c,	(byte) 0x83,	(byte) 0x53,	(byte) 0x99,	(byte) 0x61, 
		(byte) 0x17,	(byte) 0x2b,	(byte) 0x4,	(byte) 0x7e,	(byte) 0xba, 
		(byte) 0x77,	(byte) 0xd6,	(byte) 0x26,	(byte) 0xe1,	(byte) 0x69, 
		(byte) 0x14,	(byte) 0x63,	(byte) 0x55,	(byte) 0x21,	(byte) 0xc, 
		(byte) 0x7d	}; 

	final static int[] LogTable = {
		0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 
		100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193, 
		125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120, 
		101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 
		150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 
		102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16, 
		126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186, 
		43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 
		175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232, 
		44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160, 
		127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 
		204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 
		151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 
		83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 
		68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 
		103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};

   	 final static int[] AlogTable = {
		1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53, 
		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170, 
		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49, 
		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205, 
		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154, 
		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163, 
		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 
		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 
		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 
		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 
		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202, 
		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14, 
		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23, 
		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};

	public static void main (String [] args) throws Exception{
		AES aes = new AES();
		BufferedReader brr = new BufferedReader(new FileReader(new File(args[1])));
		BufferedReader br = new BufferedReader(new FileReader(new File(args[2])));
		PrintWriter pw;
		long starttime = System.currentTimeMillis();
		String key = brr.readLine();
		if(key.length() > 32) {
			key = key.substring(0, 32);
		}
		while(key.length() < 32) {
			key += "0";
		}
		brr.close();
		byte [][] cipherkey = new byte[4][4];
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				cipherkey[j][i] = (byte)(Integer.parseInt(key.substring(((i*4)+j)*2, ((i*4)+j)*2+2), 16) & 0xFF);
			}
		}
		aes.expandKey(cipherkey);
		if(args[0].equals("e")) {
			int bytes = 0;
			pw = new PrintWriter(new FileOutputStream(args[2] + ".enc"));
			String line;
			while ((line = br.readLine()) != null) {
				if(line.length() > 32) {
					line = line.substring(0, 32);
				}
				while(line.length() < 32) {
					line += "0";
				}
				byte [][] inputbytes = new byte[4][4];
				if(line.matches("[0-9a-fA-F]+")) {
					bytes += 16;
					for(int i = 0; i < 4; i++) {
						for(int j = 0; j < 4; j++) {
							inputbytes[j][i] = (byte) (Integer.parseInt(line.substring(((i*4)+j)*2, ((i*4)+j)*2+2), 16) & 0xFF);
						}
					}
					aes.encrypt(inputbytes);
					for(int i = 0; i < 4; i++) {
                        				for(int j = 0; j < 4; j++) {
                        		        		pw.printf("%02X", aes.st[j][i]);
                	        			}
        	        		}
        	        		pw.println();
				}
			}
			pw.close();
			long endtime = System.currentTimeMillis();
			System.out.println("Total: " + (float)(bytes/1024/1024) + " Throughput: " + (float)((bytes/1024/1024)/((endtime-starttime)*0.001)));
		}
		else if(args[0].equals("d")) {
			pw = new PrintWriter(new FileOutputStream(args[2] + ".dec"));
			String line;
			int bytes = 0;
			while ((line = br.readLine()) != null) {
                                if(line.length() > 32) {
                                        line = line.substring(0, 32);
                                }
                                while(line.length() < 32) {
                                        line += "0";
                                }
                                byte [][] inputbytes = new byte[4][4];
				if(line.matches("[0-9a-fA-F]+")) {
					bytes += 16;
                                	for(int i = 0; i < 4; i++) {
                                	        for(int j = 0; j < 4; j++) {
                                	                inputbytes[j][i] = (byte) (Integer.parseInt(line.substring(((i*4)+j)*2, ((i*4)+j)*2+2), 16) & 0xFF);
                                	        }
                                	}
                                	aes.decrypt(inputbytes);
                                	for(int i = 0; i < 4; i++) {
                                	                for(int j = 0; j < 4; j++) {
                                	                        pw.printf("%02X", aes.st[j][i]);
                                	                }
                                	}
                                	pw.println();
				}
                        }
                        pw.close();
			long endtime = System.currentTimeMillis();
			System.out.println("Total: " + (float)(bytes/1024/1024) + " Throughput: " + (float)((bytes/1024/1024)/((endtime-starttime)*0.001)));
		}
		br.close();
			/*String input = "";
			String key = "";
			byte [][] inputbytes = new byte[4][4];
			if(input.length() > 32) {
				input = input.substring(0, 32);
			}
			while(input.length() < 32) {
				input += "0";
			}
			if(key.length() > 32) {
				key = key.substring(0, 32);
			}
			while(key.length() < 32) {
				key += "0";
			}
			int row = 0;
			System.out.println("The Plaintext is:");
			for(int i = 0; i < 4; i++) {
				for(int j = 0; j < 4; j++) {
					inputbytes[j][i] = (byte) (Integer.parseInt(input.substring(((i*4)+j)*2, ((i*4)+j)*2+2), 16) & 0xFF);
					System.out.printf("%02X ", aes.st[j][i]);
				}
				System.out.println();
			}
			System.out.println();
			byte [][] cipherkey = new byte[4][4];
			System.out.println("The Cipherkey is:");
			for(int i = 0; i < 4; i++) {
				for(int j = 0; j < 4; j++) {
					cipherkey[j][i] = (byte) (Integer.parseInt(key.substring(((i*4)+j)*2, ((i*4)+j)*2+2), 16) & 0xFF);
					System.out.printf("%02X ", cipherkey[j][i]);
				}
				System.out.println();
			}
			System.out.println();
			
			aes.expandKey(cipherkey);
			int space = 0;
			System.out.println("The expanded key is:");
			for(int i = 0; i < 4; i++) {
                        	for(int j = 0; j < 44; j++) {
                                	System.out.printf("%02X", aes.expandedKey[i][j]);
                                	space++;
                                	if(space == 4) {
                                        	System.out.print(" ");
                                        	space = 0;
                                	}
                        	}
                        	System.out.println();
                	}
			System.out.println();

			aes.encrypt(inputbytes);
			aes.printst();
			aes.decrypt(aes.st);
			aes.printst();*/
			/*
			aes.addRoundKey(0);
			System.out.println("After addRoundKey(0):");
			aes.printst();
			for(int i = 1; i < 10; i++) {
				aes.subBytes();
				System.out.println("After subBytes:");
				aes.printst();
				aes.shiftRows();
				System.out.println("After shiftRows:");
				aes.printst();
				System.out.println("After mixColumns:");
				aes.mixColumns();
				aes.printst();
				System.out.println("After addRoundKey(" + i + "):");
				aes.addRoundKey(i);
				aes.printst();
			}
			aes.subBytes();
			System.out.println("After subBytes:");
			aes.printst();
			aes.shiftRows();
			System.out.println("After shiftRows:");
			aes.printst();
			aes.addRoundKey(10);
			System.out.println("After addRoundKey(10):");
			aes.printst();
			System.out.println("The ciphertext:");
			for(int i = 0; i < 4; i++) {
				for(int j = 0; j < 4; j++) {
					System.out.printf("%02X ", aes.st[j][i]);
				}
				System.out.println();
			}

			System.out.println();

			System.out.println("After addRoundKey(10):");
			aes.addRoundKey(10);
			aes.printst();
			System.out.println("After invShiftRows:");
			aes.invShiftRows();
			aes.printst();
			System.out.println("After invSubBytes:");
			aes.invSubBytes();
			aes.printst();
			for(int i = 9; i > 0; i--) {
				System.out.println("After addRoundKey(" + i + "):");
				aes.addRoundKey(i);
				aes.printst();
				System.out.println("After invMixColumns:");
				aes.invMixColumns();
				aes.printst();
				System.out.println("After invShiftRows:");
				aes.invShiftRows();
				aes.printst();
				System.out.println("After invSubBytes:");
				aes.invSubBytes();
				aes.printst();
			}
			System.out.println("After addRoundKey(0):");
			aes.addRoundKey(0);
			aes.printst();
			System.out.println("The description of the ciphertext:");
			aes.printst();*/
	}

	void expandKey(byte [][] original) {
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				expandedKey[i][j] = original[i][j];
			}
		}
		byte Rcon[] = {(byte)0x01,(byte)0x02,(byte)0x04,(byte)0x08,(byte)0x10,(byte)0x20,(byte)0x40,(byte)0x80,(byte)0x1B,(byte)0x36};
		for(int i = 0; i < 10; i++) {
			expandedKey[0][i*4+4] = (byte)(S[(int)expandedKey[1][i*4+3]&0xFF] ^ expandedKey[0][i*4] ^ Rcon[i]);
			expandedKey[1][i*4+4] = (byte)(S[(int)expandedKey[2][i*4+3]&0xFF] ^ expandedKey[1][i*4]);
			expandedKey[2][i*4+4] = (byte)(S[(int)expandedKey[3][i*4+3]&0xFF] ^ expandedKey[2][i*4]);
			expandedKey[3][i*4+4] = (byte)(S[(int)expandedKey[0][i*4+3]&0xFF] ^ expandedKey[3][i*4]);
			
			for(int j = 1; j < 4; j++) {
				expandedKey[0][4*i+j+4] = (byte)(expandedKey[0][i*4+3+j] ^ expandedKey[0][i*4+j]);
				expandedKey[1][4*i+j+4] = (byte)(expandedKey[1][i*4+3+j] ^ expandedKey[1][i*4+j]);
				expandedKey[2][4*i+j+4] = (byte)(expandedKey[2][i*4+3+j] ^ expandedKey[2][i*4+j]);
				expandedKey[3][4*i+j+4] = (byte)(expandedKey[3][i*4+3+j] ^ expandedKey[3][i*4+j]);

			}
		}
	}

	void encrypt(byte [][] inputbytes) {
		st = inputbytes;
		addRoundKey(0);
		for(int i = 1; i < 10; i++) {
			subBytes();
			shiftRows();
			mixColumns();
			addRoundKey(i);
		}
		subBytes();
		shiftRows();
		addRoundKey(10);
	}

	void decrypt(byte [][] inputbytes) {
		st = inputbytes;
		addRoundKey(10);
		invShiftRows();
		invSubBytes();
		for(int i = 9; i > 0; i--) {
			addRoundKey(i);
			invMixColumns();
			invShiftRows();
			invSubBytes();
		}
		addRoundKey(0);
	}

	void subBytes() {
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				st[i][j] = S[(int)st[i][j] & 0xFF];
			}
		}
	}

	void invSubBytes() {
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				st[i][j] = Si[(int)st[i][j] & 0xFF];
			}
		}
	}

	void shiftRows() {
		rotate(1);
		rotate(2);
		rotate(2);
		rotate(3);
		rotate(3);
		rotate(3);
	}

	void invShiftRows() {
		invRotate(1);
		invRotate(2);
		invRotate(2);
		invRotate(3);
		invRotate(3);
		invRotate(3);
	}

	void rotate(int rownum) {
		byte temp1 = st[rownum][0];
		byte temp2 = st[rownum][1];
		byte temp3 = st[rownum][2];
		byte temp4 = st[rownum][3];
		st[rownum][0] = temp2;
		st[rownum][1] = temp3;
		st[rownum][2] = temp4;
		st[rownum][3] = temp1;
	}

	void invRotate(int rownum) {
		byte temp1 = st[rownum][0];
		byte temp2 = st[rownum][1];
		byte temp3 = st[rownum][2];
		byte temp4 = st[rownum][3];
		st[rownum][0] = temp4;
		st[rownum][1] = temp1;
		st[rownum][2] = temp2;
		st[rownum][3] = temp3;
	}

	void mixColumns() {
		mixColumn2(0);
		mixColumn2(1);
		mixColumn2(2);
		mixColumn2(3);
	}

	void invMixColumns() {
		invMixColumn2(0);
		invMixColumn2(1);
		invMixColumn2(2);
		invMixColumn2(3);
	}

	private byte mul (int a, byte b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;
	
		if ( (a != 0) && (b != 0) ) {
		    int index = (LogTable[inda] + LogTable[indb]);
		    byte val = (byte)(AlogTable[ index % 255 ] );
		    return val;
		}
		else 
		    return 0;
	} // mul
	
	    // In the following two methods, the input c is the column number in
	    // your evolving state matrix st (which originally contained 
	    // the plaintext input but is being modified).  Notice that the state here is defined as an
	    // array of bytes.  If your state is an array of integers, you'll have
	    // to make adjustments. 
	
   	public void mixColumn2 (int c) {
		// This is another alternate version of mixColumn, using the 
		// logtables to do the computation.
		
		byte a[] = new byte[4];
	
		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++) 
		    a[i] = st[i][c];
		
		// This is exactly the same as mixColumns1, if 
		// the mul columns somehow match the b columns there.
		st[0][c] = (byte)(mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
		st[1][c] = (byte)(mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
		st[2][c] = (byte)(mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
		st[3][c] = (byte)(mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));
    	} // mixColumn2

    	public void invMixColumn2 (int c) {
		byte a[] = new byte[4];
	
		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++) 
		    a[i] = st[i][c];
		
		st[0][c] = (byte)(mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]));
		st[1][c] = (byte)(mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]));
		st[2][c] = (byte)(mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]));
		st[3][c] = (byte)(mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]));
     	} // invMixColumn2

	public void addRoundKey (int c) {
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				st[i][j] ^= expandedKey[i][c*4+j];
			}
		}
	}

	public void printst() {
		for(int i = 0; i < 4; i++) {
			for(int j = 0; j < 4; j++) {
				System.out.printf("%02X", st[j][i]);
			}
		}
		System.out.println();
	}
}
