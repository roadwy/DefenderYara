
rule Trojan_Win64_CobaltStrike_AH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 48 63 d0 48 8b 4c 24 ?? 48 8b 44 24 ?? 42 0f b6 04 00 88 04 11 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c8 48 8b 05 ?? ?? ?? 00 31 0d ?? ?? ?? 00 49 63 48 ?? 41 8b d1 c1 ea 10 88 14 01 } //2
		$a_03_1 = {48 8b 44 24 ?? 80 e9 ?? 32 0d ?? ?? ?? 00 41 88 0c 02 41 0f b7 44 5e } //2
		$a_03_2 = {44 03 c9 8b 53 ?? 33 c9 41 81 f0 00 30 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 49 89 f0 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 89 f9 e8 ?? ?? ?? ?? 48 c7 44 24 20 ?? ?? ?? ?? 41 b9 ?? ?? ?? ?? 48 c7 c1 } //5
		$a_80_1 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 46 75 6c 6c } //EtwEventWriteFull  1
		$a_80_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //notepad.exe  1
		$a_80_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 01 ff 43 ?? 8b 83 ?? ?? ?? ?? 33 83 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 48 63 4b ?? 2d ?? ?? ?? ?? 31 43 ?? 48 8b 43 ?? 44 88 04 01 ff 43 ?? 8b 43 ?? 33 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 31 43 ?? 8b 43 ?? 2b 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_AH_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 10 83 c2 01 48 83 c0 01 0f b6 d2 48 39 c8 75 ef } //1
		$a_01_1 = {58 51 43 40 56 45 52 6b 7a 5e 54 45 58 44 58 51 43 6b 60 5e 59 53 58 40 44 6b 74 42 45 45 52 59 43 61 52 45 44 5e 58 59 6b 65 42 59 37 } //1 XQC@VERkz^TEXDXQCk`^YSX@DktBEERYCaRED^XYkeBY7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}