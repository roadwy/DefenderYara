
rule TrojanSpy_Win32_CobaltStrike_STE_{
	meta:
		description = "TrojanSpy:Win32/CobaltStrike.STE!!CobaltStrike.STE,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 } //01 00 
		$a_03_1 = {2f 70 6f 73 74 73 2f 90 02 10 2f 69 76 63 2f 90 00 } //01 00 
		$a_01_2 = {e9 91 01 00 00 e9 c9 01 00 00 e8 8b ff ff ff } //01 00 
		$a_03_3 = {68 6e 65 74 00 68 77 69 6e 69 90 01 01 68 4c 77 26 07 ff 90 00 } //0a 00 
	condition:
		any of ($a_*)
 
}