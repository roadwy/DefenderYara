
rule Trojan_Win64_Cobaltstrike_DT_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 7d 35 48 8b 44 24 08 0f b6 00 33 44 24 38 48 8b 4c 24 08 88 01 48 8b 44 24 08 0f b6 00 2b 44 24 30 48 8b 4c 24 08 88 01 48 8b 44 24 08 48 ff c0 48 89 44 24 08 eb } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_DT_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 4d 61 69 6e } //0a 00  DllMain
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {70 62 6d 62 64 75 61 75 2e 64 6c 6c } //01 00  pbmbduau.dll
		$a_81_3 = {64 6f 65 71 7a 68 73 77 65 74 61 71 7a 75 72 74 6b } //01 00  doeqzhswetaqzurtk
		$a_81_4 = {66 66 67 71 63 78 7a 68 65 70 75 72 65 6c 61 69 6a } //01 00  ffgqcxzhepurelaij
		$a_81_5 = {6a 6e 73 78 64 61 6b 68 64 6f 66 78 78 71 } //01 00  jnsxdakhdofxxq
		$a_81_6 = {6b 70 71 68 62 6a 68 6f 73 61 65 61 72 75 73 } //00 00  kpqhbjhosaearus
	condition:
		any of ($a_*)
 
}