
rule Backdoor_BAT_Bladabindi_MBKS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 08 6f 90 01 01 00 00 0a 00 73 90 01 01 00 00 0a 0d 09 07 6f 90 01 01 00 00 0a 00 09 04 6f 90 01 01 00 00 0a 00 09 05 6f 90 01 01 00 00 0a 00 09 6f 90 01 01 00 00 0a 13 04 11 04 02 16 02 8e 69 6f 90 00 } //10
		$a_01_1 = {30 35 65 34 61 34 63 36 2d 64 62 63 32 2d 34 63 61 38 2d 62 33 64 62 2d 34 36 32 63 64 35 61 38 33 66 38 32 } //1 05e4a4c6-dbc2-4ca8-b3db-462cd5a83f82
		$a_01_2 = {69 6d 66 72 65 65 32 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 imfree2.Resources.resource
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}