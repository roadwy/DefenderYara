
rule Trojan_Win64_BazarLoader_AH_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {46 24 49 64 75 69 7a 34 } //F$Iduiz4  3
		$a_80_1 = {47 65 6d 70 6c 75 73 20 47 65 6d 53 41 46 45 20 43 61 72 64 20 43 53 50 20 76 31 2e 30 } //Gemplus GemSAFE Card CSP v1.0  3
		$a_80_2 = {53 79 73 74 65 6d 33 32 5c 44 52 49 56 45 52 53 5c 61 73 79 6e 63 6d 61 63 2e 73 79 73 } //System32\DRIVERS\asyncmac.sys  3
		$a_80_3 = {5f 69 74 6f 61 } //_itoa  3
		$a_80_4 = {4d 70 56 72 65 67 4f 70 65 6e 4b 65 79 53 75 63 63 65 73 73 } //MpVregOpenKeySuccess  3
		$a_80_5 = {74 65 73 74 73 76 63 2e 65 78 65 } //testsvc.exe  3
		$a_80_6 = {57 69 6e 64 6f 77 73 20 42 65 65 70 20 53 65 72 76 69 63 65 } //Windows Beep Service  3
		$a_80_7 = {61 64 76 61 70 69 33 32 2e 70 64 62 } //advapi32.pdb  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}