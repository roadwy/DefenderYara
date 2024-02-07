
rule Trojan_Win64_XMRMiner_PAA_MTB{
	meta:
		description = "Trojan:Win64/XMRMiner.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 57 69 6e 52 69 6e 67 90 02 04 2e 73 79 73 90 00 } //01 00 
		$a_01_1 = {78 6d 72 69 67 2d 6e 6f 74 6c 73 2e 65 78 65 } //01 00  xmrig-notls.exe
		$a_01_2 = {5c 53 71 6c 54 6f 6f 6c 73 2e 65 78 65 } //01 00  \SqlTools.exe
		$a_01_3 = {70 72 6f 63 65 78 70 36 34 2e 65 78 65 } //01 00  procexp64.exe
		$a_01_4 = {70 72 6f 63 65 78 70 2e 65 78 65 } //01 00  procexp.exe
		$a_01_5 = {73 6f 6b 65 72 73 2e 65 78 65 } //01 00  sokers.exe
		$a_01_6 = {78 6d 72 69 67 2e 65 78 65 } //01 00  xmrig.exe
		$a_01_7 = {6e 73 73 6d 2e 65 78 65 } //00 00  nssm.exe
	condition:
		any of ($a_*)
 
}