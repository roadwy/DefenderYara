
rule HackTool_MacOS_Fscan_C_MTB{
	meta:
		description = "HackTool:MacOS/Fscan.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 77 64 43 72 61 63 6b 53 63 61 6e } //1 PwdCrackScan
		$a_01_1 = {53 63 61 6e 57 69 74 68 50 72 6f 62 65 73 46 6f 72 43 72 61 63 6b } //1 ScanWithProbesForCrack
		$a_01_2 = {54 61 72 67 65 74 57 65 62 53 63 61 6e 46 6f 72 46 69 6e 67 65 72 41 6e 64 50 6f 63 } //1 TargetWebScanForFingerAndPoc
		$a_01_3 = {47 65 74 48 6f 73 74 43 72 61 63 6b 49 70 73 } //1 GetHostCrackIps
		$a_01_4 = {49 6e 73 65 72 74 50 77 64 43 72 61 63 6b 44 42 } //1 InsertPwdCrackDB
		$a_01_5 = {47 65 74 50 77 64 43 72 61 63 6b 54 61 62 44 61 74 61 } //1 GetPwdCrackTabData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}