
rule Trojan_Win64_CobaltStrike_AH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 48 63 d0 48 8b 4c 24 90 01 01 48 8b 44 24 90 01 01 42 0f b6 04 00 88 04 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 89 c2 49 89 f0 e8 90 01 04 48 8d 15 90 01 04 48 89 f9 e8 90 01 04 48 c7 44 24 20 90 01 04 41 b9 90 01 04 48 c7 c1 90 00 } //01 00 
		$a_80_1 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 46 75 6c 6c } //EtwEventWriteFull  01 00 
		$a_80_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //notepad.exe  01 00 
		$a_80_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 43 90 01 01 8b 83 90 01 04 33 83 90 01 04 35 90 01 04 89 83 90 01 04 8b 83 90 01 04 48 63 4b 90 01 01 2d 90 01 04 31 43 90 01 01 48 8b 43 90 01 01 44 88 04 01 ff 43 90 01 01 8b 43 90 01 01 33 83 90 01 04 2d 90 01 04 31 43 90 01 01 8b 43 90 01 01 2b 83 90 01 04 2d 90 01 04 01 83 90 01 04 49 81 f9 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 10 83 c2 01 48 83 c0 01 0f b6 d2 48 39 c8 75 ef } //01 00 
		$a_01_1 = {58 51 43 40 56 45 52 6b 7a 5e 54 45 58 44 58 51 43 6b 60 5e 59 53 58 40 44 6b 74 42 45 45 52 59 43 61 52 45 44 5e 58 59 6b 65 42 59 37 } //00 00  XQC@VERkz^TEXDXQCk`^YSX@DktBEERYCaRED^XYkeBY7
	condition:
		any of ($a_*)
 
}