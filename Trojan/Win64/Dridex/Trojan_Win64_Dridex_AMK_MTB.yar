
rule Trojan_Win64_Dridex_AMK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {b8 6f 8d 0d 00 89 04 24 89 44 24 04 8b 04 24 03 44 24 04 69 d0 ab aa aa aa 81 c2 aa aa aa 2a 8b 04 24 81 fa 55 55 55 55 72 64 05 9b 66 25 02 } //10
		$a_80_1 = {64 75 69 65 72 } //duier  3
		$a_80_2 = {67 6c 6f 70 69 71 } //glopiq  3
		$a_80_3 = {6a 70 71 64 72 } //jpqdr  3
		$a_80_4 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //GetCurrentThreadId  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}