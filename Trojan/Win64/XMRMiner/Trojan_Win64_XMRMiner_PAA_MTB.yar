
rule Trojan_Win64_XMRMiner_PAA_MTB{
	meta:
		description = "Trojan:Win64/XMRMiner.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {5c 57 69 6e 52 69 6e 67 [0-04] 2e 73 79 73 } //1
		$a_01_1 = {78 6d 72 69 67 2d 6e 6f 74 6c 73 2e 65 78 65 } //1 xmrig-notls.exe
		$a_01_2 = {5c 53 71 6c 54 6f 6f 6c 73 2e 65 78 65 } //1 \SqlTools.exe
		$a_01_3 = {70 72 6f 63 65 78 70 36 34 2e 65 78 65 } //1 procexp64.exe
		$a_01_4 = {70 72 6f 63 65 78 70 2e 65 78 65 } //1 procexp.exe
		$a_01_5 = {73 6f 6b 65 72 73 2e 65 78 65 } //1 sokers.exe
		$a_01_6 = {78 6d 72 69 67 2e 65 78 65 } //1 xmrig.exe
		$a_01_7 = {6e 73 73 6d 2e 65 78 65 } //1 nssm.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}