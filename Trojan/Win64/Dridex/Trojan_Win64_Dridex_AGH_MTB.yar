
rule Trojan_Win64_Dridex_AGH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {57 42 71 74 68 65 64 61 6e 69 65 6c 6c 65 } //WBqthedanielle  3
		$a_80_1 = {64 69 64 77 62 44 62 69 67 64 61 64 64 79 77 65 65 6b } //didwbDbigdaddyweek  3
		$a_80_2 = {72 6d 69 23 64 52 66 2e 70 64 62 } //rmi#dRf.pdb  3
		$a_80_3 = {4a 65 74 4d 61 6b 65 4b 65 79 } //JetMakeKey  3
		$a_80_4 = {53 43 61 72 64 47 65 74 43 61 72 64 54 79 70 65 50 72 6f 76 69 64 65 72 4e 61 6d 65 57 } //SCardGetCardTypeProviderNameW  3
		$a_80_5 = {49 6e 74 65 72 6c 6f 63 6b 65 64 50 75 73 68 45 6e 74 72 79 53 4c 69 73 74 } //InterlockedPushEntrySList  3
		$a_80_6 = {53 65 74 53 79 73 74 65 6d 54 69 6d 65 41 64 6a 75 73 74 6d 65 6e 74 } //SetSystemTimeAdjustment  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}