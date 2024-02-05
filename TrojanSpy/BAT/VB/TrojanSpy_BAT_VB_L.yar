
rule TrojanSpy_BAT_VB_L{
	meta:
		description = "TrojanSpy:BAT/VB.L,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {66 74 70 5f 75 70 6c 6f 61 64 5f 4e 65 77 78 46 75 63 6b } //04 00 
		$a_01_1 = {46 70 74 5f 46 75 63 6b 5f 41 6c 6c 49 6e 4f 6e 65 5f 55 70 6c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}