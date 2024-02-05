
rule TrojanSpy_BAT_Noon_SP_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 cd 09 00 70 28 90 01 03 06 1a 2d 03 26 de 06 0a 2b fb 90 00 } //01 00 
		$a_01_1 = {66 76 75 61 38 74 62 34 66 37 37 67 64 6d 66 77 71 78 67 72 79 6a 6a 77 37 65 35 38 36 33 38 75 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}