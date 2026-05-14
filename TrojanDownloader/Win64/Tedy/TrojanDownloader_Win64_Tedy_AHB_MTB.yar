
rule TrojanDownloader_Win64_Tedy_AHB_MTB{
	meta:
		description = "TrojanDownloader:Win64/Tedy.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 1c be da 6c 12 c7 45 20 ab f3 b1 3a c7 45 24 7a 90 d1 07 66 c7 45 28 19 00 } //30
		$a_03_1 = {0f b6 cb 80 e1 ?? c0 e1 ?? 41 b9 ?? ?? ?? ?? 41 d3 e9 44 32 4c 1c 30 0f be c3 6b c8 ?? 44 32 c9 49 3b d0 73 } //20
		$a_81_2 = {73 63 20 73 74 6f 70 20 41 41 } //10 sc stop AA
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20+(#a_81_2  & 1)*10) >=60
 
}