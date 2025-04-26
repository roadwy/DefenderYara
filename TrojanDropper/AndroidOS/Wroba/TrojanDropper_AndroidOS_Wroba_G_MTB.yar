
rule TrojanDropper_AndroidOS_Wroba_G_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Wroba.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {06 46 20 68 59 46 32 46 4b 46 cd f8 3c 90 d0 f8 88 50 20 46 a8 47 20 68 df f8 c4 15 d0 f8 9c 22 79 44 20 46 90 47 03 46 20 68 59 46 32 46 } //1
		$a_00_1 = {4c 89 f6 ff 90 08 01 00 00 48 89 c3 49 8b 2f 31 c0 4c 89 ff 4c 89 ee 48 89 da 4c 89 64 24 68 4c 89 e1 ff 95 10 01 00 00 49 8b 07 48 8d 35 75 0a 00 00 4c 89 ff ff 90 38 05 00 00 48 89 c1 49 8b 2f 31 c0 4c 89 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}