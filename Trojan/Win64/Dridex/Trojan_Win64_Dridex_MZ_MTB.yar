
rule Trojan_Win64_Dridex_MZ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.MZ!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {66 42 47 54 2e 70 64 62 } //1 fBGT.pdb
		$a_01_1 = {6e 65 6c 65 72 36 2e 64 6c 6c } //1 neler6.dll
		$a_01_2 = {53 65 63 75 72 33 32 2e 64 6c 6c } //1 Secur32.dll
		$a_01_3 = {46 6c 6f 6f 64 46 69 6c 6c } //1 FloodFill
		$a_01_4 = {43 52 59 50 54 33 32 2e 64 6c 6c } //1 CRYPT32.dll
		$a_01_5 = {67 5f 72 67 53 43 61 72 64 54 31 50 63 69 } //1 g_rgSCardT1Pci
		$a_01_6 = {57 69 6e 53 43 61 72 64 2e 64 6c 6c } //1 WinSCard.dll
		$a_01_7 = {57 00 74 00 63 00 64 00 48 00 69 00 71 00 65 00 67 00 2e 00 71 00 74 00 78 00 } //1 WtcdHiqeg.qtx
		$a_01_8 = {6f 49 6e 45 43 61 6e 61 72 79 79 69 74 43 68 72 6f 6d 65 } //1 oInECanaryyitChrome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}