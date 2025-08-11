
rule TrojanSpy_BAT_Noon_SQK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 09 00 00 70 6f 03 00 00 0a 6f 04 00 00 0a 6f 05 00 00 0a 6f 06 00 00 0a 6f 07 00 00 0a 0a dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanSpy_BAT_Noon_SQK_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Noon.SQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 11 06 11 0e 91 6f d5 00 00 0a 00 00 11 0e 17 58 13 0e 11 0e 11 07 fe 04 13 0f 11 0f 2d e0 } //2
		$a_01_1 = {47 4d 53 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 GMS.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}