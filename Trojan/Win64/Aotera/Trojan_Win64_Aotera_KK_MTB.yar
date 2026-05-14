
rule Trojan_Win64_Aotera_KK_MTB{
	meta:
		description = "Trojan:Win64/Aotera.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d1 41 8b 54 96 10 43 89 54 8e 10 8b d1 45 89 5c 96 10 41 ff c1 41 81 f9 00 01 00 00 } //20
		$a_01_1 = {41 8b c3 41 0f b6 44 86 10 33 d0 41 8b c1 88 54 01 10 41 ff c1 41 3b f9 } //10
		$a_01_2 = {41 c1 e7 04 41 0b c7 42 88 44 37 10 83 c5 02 41 ff c6 3b ee 7c c0 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win64_Aotera_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Aotera.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8b c9 46 0f b6 4c 0e ?? 49 03 d1 49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 49 0f af d1 4c 8b ca 49 c1 e9 1c 49 33 d1 ff c1 44 3b c1 } //20
		$a_03_1 = {49 03 d0 4c 8b c2 49 c1 e8 ?? 4c 33 c2 49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 4d 0f af c1 4d 8b c8 49 c1 e9 ?? 4d 33 c1 49 b9 ?? ?? ?? ?? ?? ?? ?? ?? 4d 0f af c1 4d 8b c8 49 c1 e9 ?? 4d 33 c1 44 8b c9 4e 89 44 c8 ?? ff c1 83 f9 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}