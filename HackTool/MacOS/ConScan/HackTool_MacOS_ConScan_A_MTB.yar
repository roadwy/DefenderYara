
rule HackTool_MacOS_ConScan_A_MTB{
	meta:
		description = "HackTool:MacOS/ConScan.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 74 6f 6f 6c 2f 70 72 6f 62 65 2e 53 63 61 6e 50 6f 72 74 } //1 /tool/probe.ScanPort
		$a_01_1 = {2f 70 6b 67 2f 70 6c 75 67 69 6e 2e 52 75 6e 53 69 6e 67 6c 65 45 78 70 6c 6f 69 74 } //1 /pkg/plugin.RunSingleExploit
		$a_01_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 63 64 6b 2d 74 65 61 6d 2f 43 44 4b 2f 70 6b 67 2f 65 78 70 6c 6f 69 74 } //1 github.com/cdk-team/CDK/pkg/exploit
		$a_01_3 = {2f 74 6f 6f 6c 2f 70 72 6f 62 65 2e 54 43 50 53 63 61 6e 45 78 70 6c 6f 69 74 41 50 49 } //1 /tool/probe.TCPScanExploitAPI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}