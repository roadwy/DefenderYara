
rule Trojan_Win64_Tedy_AHB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 55 44 46 43 6f 6d 70 61 6e 69 6f 6e 48 6f 73 74 65 2e 65 78 65 } //20 WUDFCompanionHoste.exe
		$a_01_1 = {53 74 61 72 74 4d 65 6e 75 45 78 70 65 72 69 65 6e 63 65 48 6f 73 74 6b 65 72 2e 65 78 65 } //30 StartMenuExperienceHostker.exe
		$a_03_2 = {48 2b c8 0f b6 44 0c 70 41 30 40 ?? 49 83 c0 ?? 4b 8d 04 01 48 3d ?? ?? ?? ?? 0f } //50
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30+(#a_03_2  & 1)*50) >=100
 
}