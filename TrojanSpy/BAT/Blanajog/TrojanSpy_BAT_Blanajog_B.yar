
rule TrojanSpy_BAT_Blanajog_B{
	meta:
		description = "TrojanSpy:BAT/Blanajog.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 6a 4c 6f 67 67 65 72 } //01 00 
		$a_01_1 = {4c 61 73 74 41 56 } //01 00 
		$a_01_2 = {6f 00 70 00 65 00 6e 00 6b 00 6c 00 } //01 00 
		$a_01_3 = {67 00 65 00 74 00 6c 00 6f 00 67 00 73 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}