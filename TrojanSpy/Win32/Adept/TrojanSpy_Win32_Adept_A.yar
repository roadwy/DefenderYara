
rule TrojanSpy_Win32_Adept_A{
	meta:
		description = "TrojanSpy:Win32/Adept.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {80 fb 0a 74 15 80 fb 0d 74 10 8b c6 99 f7 7d 90 01 01 8b 45 90 01 01 8a 04 02 32 c3 88 01 90 00 } //01 00 
		$a_03_1 = {74 37 66 81 7d 10 bb 01 74 07 68 90 01 04 eb 05 90 00 } //01 00 
		$a_01_2 = {5f 4f 5f 4b 5f } //01 00 
		$a_01_3 = {53 74 61 72 74 20 41 75 64 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}