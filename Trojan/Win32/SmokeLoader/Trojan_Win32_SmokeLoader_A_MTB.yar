
rule Trojan_Win32_SmokeLoader_A_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 54 24 18 8b 4c 24 1c d3 ea 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 20 31 44 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_A_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 47 86 c8 61 03 45 e4 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85 01 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SmokeLoader_A_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {6d 69 64 65 7a 6f 79 6f 62 75 67 61 6c 6f 64 6f 6c 6f 62 75 76 65 6c 65 6c 65 7a 6f 63 6f 6b 61 6b 75 66 6f 66 61 66 61 63 61 } //01 00 
		$a_81_1 = {73 65 67 6f 70 65 7a 65 68 75 79 6f 72 6f 73 65 63 65 } //01 00 
		$a_81_2 = {6b 6b 75 72 69 6b 6f 6c 69 73 69 64 75 64 69 67 75 79 69 6b } //01 00 
		$a_81_3 = {53 6f 6c 6f 66 75 64 69 20 67 6f 78 6f 72 75 76 20 73 61 70 6f 63 75 7a 69 } //01 00 
		$a_81_4 = {61 6c 6c 6f 63 61 20 77 61 73 20 63 6f 72 72 75 70 74 65 64 } //01 00 
		$a_81_5 = {66 3a 5c 64 64 5c 76 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}