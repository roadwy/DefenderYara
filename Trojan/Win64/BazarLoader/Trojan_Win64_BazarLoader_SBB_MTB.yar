
rule Trojan_Win64_BazarLoader_SBB_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.SBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {48 83 ec 48 c7 44 24 30 e4 ff ee 31 45 33 d2 c7 44 24 34 90 01 04 8b 44 24 30 44 88 54 24 38 8a 44 24 38 84 c0 75 90 00 } //03 00 
		$a_80_1 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //ActivateKeyboardLayout  03 00 
		$a_80_2 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //GetKeyboardLayout  03 00 
		$a_80_3 = {58 77 4a 41 4e 69 4a 54 59 7a 5a 44 77 4e 71 30 } //XwJANiJTYzZDwNq0  00 00 
	condition:
		any of ($a_*)
 
}