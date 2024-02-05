
rule Trojan_Win64_BazarLoader_GE_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 89 64 24 38 4c 89 64 24 30 48 2b fb 48 d1 ff 4c 8b c3 33 d2 44 8d 4f 01 33 c9 44 89 64 24 28 4c 89 64 24 20 } //03 00 
		$a_81_1 = {76 57 32 7a 44 53 4d 4b 54 6a 7a 26 51 72 4a 4e 6f 6a 72 55 4b 68 43 79 6a 30 30 42 } //00 00 
	condition:
		any of ($a_*)
 
}