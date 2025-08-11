
rule TrojanDropper_AndroidOS_SAgnt_U_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/SAgnt.U!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {21 46 32 46 00 96 17 f0 68 ea 01 98 17 f0 96 ee 0a 48 00 21 00 22 78 44 17 f0 98 ee 08 49 02 20 01 9a 79 44 } //2
		$a_01_1 = {78 58 2c 6f cf f8 cb 3e 1a 8a b9 50 af 65 0a 0b 2e d5 20 50 76 a5 48 fd 86 35 85 13 8c 17 6d 99 1e 6d fc a4 ca 49 d4 62 41 94 a4 36 24 1d 04 50 a9 c8 67 c8 9d 7b 87 36 6a b0 b8 8e 1c 42 23 b3 0c 8a 1f c5 c4 24 53 1d 5f 4a 2e b6 a8 } //1
		$a_01_2 = {34 27 13 93 2f e9 9b 13 33 74 a0 7d 7c 80 34 94 58 27 51 0a b2 9b bc 37 86 d6 5b e4 47 bb 69 5f d3 8b 87 63 95 32 16 90 91 42 ec 6a 5b 78 0c a0 b4 99 04 25 f7 b4 7b 29 4f 74 f6 da 63 60 2b 1e ed 21 d9 5f eb 9e 50 76 9a 02 38 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}