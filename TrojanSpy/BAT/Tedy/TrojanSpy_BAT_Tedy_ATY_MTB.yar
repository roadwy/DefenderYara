
rule TrojanSpy_BAT_Tedy_ATY_MTB{
	meta:
		description = "TrojanSpy:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 3d 00 08 28 90 01 03 06 0d 09 17 2e 0a 09 20 01 80 00 00 fe 01 2b 01 17 13 04 11 04 2c 1b 00 07 72 01 00 00 70 08 d1 8c 13 00 00 01 28 90 00 } //01 00 
		$a_01_1 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6c 00 6f 00 67 00 } //01 00 
		$a_01_2 = {47 00 65 00 74 00 4b 00 65 00 79 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}