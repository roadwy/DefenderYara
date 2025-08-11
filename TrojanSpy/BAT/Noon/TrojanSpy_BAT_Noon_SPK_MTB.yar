
rule TrojanSpy_BAT_Noon_SPK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 0b 00 07 02 7b a8 01 00 04 2f 06 07 19 fe 04 2b 01 16 0c 08 2d d2 } //2
		$a_81_1 = {51 4c 42 48 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 QLBH.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
rule TrojanSpy_BAT_Noon_SPK_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Noon.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 11 21 11 22 91 6f 59 00 00 0a 00 72 f1 01 00 70 12 22 28 4e 00 00 0a 28 4f 00 00 0a 13 05 00 11 22 17 58 13 22 11 22 11 1a fe 04 13 23 11 23 2d cd } //2
		$a_01_1 = {53 74 49 76 65 73 4c 69 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 StIvesLib.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}