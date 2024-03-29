
rule Ransom_Win32_Kisucrypt_A{
	meta:
		description = "Ransom:Win32/Kisucrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 09 00 00 03 00 "
		
	strings :
		$a_01_0 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46 } //03 00 
		$a_03_1 = {83 c0 3c 8b 00 03 c2 83 c0 78 8b 00 03 c2 8b f8 83 c0 20 8b 00 03 c2 33 f6 50 8b 00 03 c2 bb 90 01 04 8a 08 8a 2b 84 c9 90 00 } //03 00 
		$a_01_2 = {80 38 00 74 30 80 78 01 00 74 20 80 78 02 00 74 10 80 78 03 00 75 e6 } //03 00 
		$a_01_3 = {8d 57 10 c7 04 10 2a 2e 2a 00 ff 75 f4 8d 47 10 50 } //03 00 
		$a_01_4 = {80 7a 2c 2e 74 06 80 7a 2d 00 75 14 80 7a 2c 2e 0f 84 a3 00 00 00 80 7a 2c 2e } //03 00 
		$a_00_5 = {47 6f 20 74 6f 20 68 74 74 70 3a 2f 2f 62 69 74 6d 65 73 73 61 67 65 2e 6f 72 67 2f } //01 00  Go to http://bitmessage.org/
		$a_00_6 = {74 61 72 2c 6a 61 72 2c 62 6d 70 2c 73 77 6d 2c 76 61 75 6c 74 2c 78 74 62 6c 2c 63 74 62 2c 31 31 33 2c 37 33 62 2c 61 33 64 2c 61 62 66 } //01 00  tar,jar,bmp,swm,vault,xtbl,ctb,113,73b,a3d,abf
		$a_00_7 = {53 55 42 4a 45 43 54 3a } //01 00  SUBJECT:
		$a_00_8 = {4d 45 53 53 41 47 45 3a } //00 00  MESSAGE:
		$a_00_9 = {5d 04 00 00 26 90 03 80 } //5c 3f 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Kisucrypt_A_2{
	meta:
		description = "Ransom:Win32/Kisucrypt.A,SIGNATURE_TYPE_PEHSTR,67 00 67 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 00 } //01 00 
		$a_01_1 = {2e 33 67 32 00 2e 33 67 70 00 2e 33 70 72 } //01 00  ㌮㉧⸀朳p㌮牰
		$a_01_2 = {73 65 63 72 65 74 2e 6b 65 79 } //01 00  secret.key
		$a_01_3 = {52 45 41 44 54 48 49 53 4e 4f 57 21 21 21 2e 74 78 74 } //64 00  READTHISNOW!!!.txt
		$a_01_4 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc 39 5d f8 75 0c 8b 55 10 89 55 f8 8b 75 f8 8a 06 46 88 45 f7 5e 58 88 07 47 49 83 f9 00 75 cd } //00 00 
		$a_01_5 = {00 67 16 00 00 62 42 bd 22 c8 a0 fd 65 ce 9d 78 1e 00 1a 05 00 01 20 86 23 34 db 67 16 00 00 27 eb a0 7c f4 b3 05 8c 31 fc dc 99 00 06 03 00 01 20 0a e4 b7 52 67 16 00 00 37 e1 0e 97 a7 01 24 28 87 2c bf d3 63 88 03 00 01 20 4b 96 c3 32 78 06 01 00 0b 00 0b 00 09 00 00 03 00 11 01 8a 06 46 32 45 f7 } //50 56 
	condition:
		any of ($a_*)
 
}