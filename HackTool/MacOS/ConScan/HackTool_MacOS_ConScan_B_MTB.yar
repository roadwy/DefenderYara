
rule HackTool_MacOS_ConScan_B_MTB{
	meta:
		description = "HackTool:MacOS/ConScan.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6b 67 2f 65 78 70 6c 6f 69 74 2e 44 49 4e 44 41 74 74 61 63 6b 53 2e 52 75 6e } //1 pkg/exploit.DINDAttackS.Run
		$a_01_1 = {2a 65 78 70 6c 6f 69 74 2e 44 49 4e 44 41 74 74 61 63 6b 44 65 70 6c 6f 79 53 } //1 *exploit.DINDAttackDeployS
		$a_01_2 = {70 6b 67 2f 65 78 70 6c 6f 69 74 2e 52 65 76 65 72 73 65 53 68 65 6c 6c } //1 pkg/exploit.ReverseShell
		$a_01_3 = {2a 65 78 70 6c 6f 69 74 2e 4b 38 73 53 65 63 72 65 74 73 44 75 6d 70 53 } //1 *exploit.K8sSecretsDumpS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}