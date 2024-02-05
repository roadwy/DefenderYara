
rule TrojanDropper_AndroidOS_Wroba_D_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {00 23 78 44 a4 f8 48 30 7a 44 08 30 84 f8 4a 30 c4 e9 00 02 04 f1 08 00 40 22 fe f7 f0 ee 04 f1 50 00 4f f4 99 71 fe f7 e4 ee 20 46 00 21 } //0a 00 
		$a_00_1 = {00 23 78 44 a4 f8 48 30 7a 44 08 30 84 f8 4a 30 c4 e9 00 02 04 f1 08 00 40 22 fe f7 82 ef 04 f1 50 00 4f f4 99 71 fe f7 76 ef 20 46 00 21 } //0a 00 
		$a_00_2 = {00 23 78 44 a4 f8 48 30 7a 44 08 30 84 f8 4a 30 c4 e9 00 02 04 f1 08 00 40 22 fe f7 1a ef 04 f1 50 00 4f f4 99 71 fe f7 0e ef 20 46 00 21 } //01 00 
		$a_01_3 = {63 6f 6d 2e 4c 6f 61 64 65 72 } //01 00 
		$a_01_4 = {2f 56 6f 6c 75 6d 65 73 2f 41 6e 64 72 6f 69 64 2f 62 75 69 6c 64 62 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}