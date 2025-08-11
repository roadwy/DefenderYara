
rule HackTool_Linux_Fscan_B_MTB{
	meta:
		description = "HackTool:Linux/Fscan.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 48 6f 73 74 43 72 61 63 6b 49 70 73 } //2 GetHostCrackIps
		$a_01_1 = {47 65 74 50 77 64 43 72 61 63 6b 54 61 62 44 61 74 61 } //2 GetPwdCrackTabData
		$a_01_2 = {47 65 74 43 79 62 65 72 54 61 62 44 61 74 61 } //2 GetCyberTabData
		$a_01_3 = {54 61 72 67 65 74 57 65 62 53 63 61 6e 46 6f 72 46 69 6e 67 65 72 41 6e 64 50 6f 63 } //1 TargetWebScanForFingerAndPoc
		$a_01_4 = {50 77 64 43 72 61 63 6b 53 63 61 6e } //1 PwdCrackScan
		$a_01_5 = {6e 75 63 6c 65 69 73 65 72 76 65 72 61 63 63 65 73 73 64 65 76 69 63 65 72 6f 75 74 65 72 63 61 6d 65 72 61 4e 75 63 6c 65 69 } //1 nucleiserveraccessdeviceroutercameraNuclei
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}