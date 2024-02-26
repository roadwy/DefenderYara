
rule Trojan_Win64_CobaltStrike_DK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 28 4c 08 d0 0f 57 c8 0f 28 54 08 e0 0f 57 d0 0f 29 4c 08 d0 0f 29 54 08 e0 0f 28 4c 08 f0 0f 57 c8 0f 28 14 08 0f 57 d0 0f 29 4c 08 f0 0f 29 14 08 48 83 c0 90 01 01 48 3d 90 02 05 75 90 00 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 43 6f 64 65 4c 6f 61 64 65 72 5c 62 69 6e } //00 00  ShellCodeLoader\bin
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_DK_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 c9 48 8d 15 90 01 02 00 00 33 04 8a b9 04 00 00 00 48 6b c9 07 48 8b 54 24 20 33 04 0a 89 44 24 1c 48 8b 44 24 20 48 83 c0 20 48 89 44 24 20 8b 44 24 2c ff c8 89 44 24 2c 83 7c 24 2c 00 75 90 00 } //02 00 
		$a_01_1 = {49 8d 04 12 41 83 c0 04 41 8b 4c 01 f8 8b 40 f8 33 0a 89 02 48 8d 52 04 41 89 4c 13 f4 44 3b 43 04 7c } //01 00 
		$a_01_2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //00 00  ReflectiveLoader
	condition:
		any of ($a_*)
 
}