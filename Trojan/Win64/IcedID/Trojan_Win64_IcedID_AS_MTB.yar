
rule Trojan_Win64_IcedID_AS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {56 79 67 68 64 73 68 75 79 67 74 66 79 47 48 6a 73 64 62 66 6b 62 68 73 67 75 61 73 6a 73 } //1 VyghdshuygtfyGHjsdbfkbhsguasjs
		$a_01_1 = {42 4d 7a 79 76 64 41 4b 42 6c 70 57 36 47 59 67 4e 35 57 72 } //1 BMzyvdAKBlpW6GYgN5Wr
		$a_01_2 = {44 53 57 55 75 42 5a 74 36 51 49 69 33 6c 50 31 47 78 43 38 33 50 62 } //1 DSWUuBZt6QIi3lP1GxC83Pb
		$a_01_3 = {4a 59 62 68 45 41 6d 66 54 72 67 72 44 36 71 53 69 47 45 53 48 6c 50 51 } //1 JYbhEAmfTrgrD6qSiGESHlPQ
		$a_01_4 = {50 6b 78 42 48 37 48 6b 6b 43 4c 4c 6a 6d 4c 70 39 } //1 PkxBH7HkkCLLjmLp9
		$a_01_5 = {55 42 50 74 37 39 78 52 56 33 45 6a 61 53 6b 62 45 52 43 38 74 46 6b 32 71 66 68 4c 58 55 44 } //1 UBPt79xRV3EjaSkbERC8tFk2qfhLXUD
		$a_01_6 = {56 39 6b 48 37 57 36 69 72 76 79 71 79 38 4b 45 4b } //1 V9kH7W6irvyqy8KEK
		$a_01_7 = {59 79 63 69 35 6d 67 6d 66 78 4d 4e 63 7a 6b 62 41 32 32 45 66 4b 62 } //1 Yyci5mgmfxMNczkbA22EfKb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}