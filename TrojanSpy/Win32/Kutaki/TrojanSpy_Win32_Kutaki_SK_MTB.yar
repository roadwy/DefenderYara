
rule TrojanSpy_Win32_Kutaki_SK_MTB{
	meta:
		description = "TrojanSpy:Win32/Kutaki.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 61 00 76 00 65 00 72 00 62 00 72 00 6f 00 } //01 00 
		$a_00_1 = {61 00 63 00 68 00 69 00 62 00 61 00 74 00 33 00 32 00 31 00 58 00 } //01 00 
		$a_01_2 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //01 00 
		$a_01_3 = {6b 69 6c 6c 65 72 6d 61 6e } //01 00 
		$a_01_4 = {6d 75 66 75 63 6b 72 } //00 00 
	condition:
		any of ($a_*)
 
}