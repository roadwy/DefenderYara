
rule Trojan_Win32_Azorult_PR_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 38 8a 44 38 01 88 4c 24 18 88 44 24 13 75 90 01 01 6a 00 6a 00 ff 15 90 01 04 8b 45 00 8a 4c 38 03 8a d1 c0 e2 06 0a 54 38 02 8a c1 24 f0 80 e1 fc c0 e0 02 83 c7 04 0a 44 24 18 c0 e1 04 0a 4c 24 13 88 04 1e 88 4c 1e 01 8b 4c 24 1c 88 54 1e 02 83 c6 03 3b 39 72 90 00 } //01 00 
		$a_03_1 = {56 57 8b 7c 24 10 33 f6 85 ff 7e 13 53 8b 5c 24 10 e8 90 01 04 30 04 1e 46 3b f7 7c f3 5b 5f 5e c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}