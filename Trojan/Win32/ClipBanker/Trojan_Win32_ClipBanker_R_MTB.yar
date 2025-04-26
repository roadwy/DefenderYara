
rule Trojan_Win32_ClipBanker_R_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 69 6c 65 6e 74 20 4d 69 6e 65 72 2e 70 64 62 } //1 Silent Miner.pdb
		$a_01_1 = {c7 45 d4 2b 73 73 7e 0f 28 05 00 c7 40 00 0f 11 45 c4 c7 45 d8 72 70 60 28 c7 45 dc 6f 74 70 00 8a 45 b4 30 44 0d b5 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ClipBanker_R_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 00 6f 00 72 00 6b 00 5c 00 66 00 65 00 6c 00 69 00 78 00 5c 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 5c 00 50 00 46 00 65 00 6c 00 69 00 78 00 2e 00 76 00 62 00 70 00 } //1 Work\felix\sources\PFelix.vbp
		$a_01_1 = {53 00 74 00 65 00 61 00 6d 00 7c 00 54 00 77 00 65 00 6c 00 76 00 65 00 53 00 6b 00 79 00 7c 00 57 00 61 00 72 00 52 00 6f 00 63 00 6b 00 } //1 Steam|TwelveSky|WarRock
		$a_01_2 = {63 00 6f 00 72 00 65 00 73 00 79 00 73 00 2e 00 65 00 78 00 65 00 } //1 coresys.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}