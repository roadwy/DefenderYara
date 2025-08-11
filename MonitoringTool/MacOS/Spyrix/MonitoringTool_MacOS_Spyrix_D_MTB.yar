
rule MonitoringTool_MacOS_Spyrix_D_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 73 70 79 72 69 78 2e 65 6d 70 2d 68 65 6c 70 65 72 } //1 com.spyrix.emp-helper
		$a_01_1 = {67 72 6f 75 70 2e 63 6f 6d 2e 73 70 79 72 69 78 2e 65 6d 70 2e 73 68 61 72 65 } //1 group.com.spyrix.emp.share
		$a_01_2 = {2f 4c 69 62 72 61 72 79 2f 65 6d 70 2f 53 70 79 72 69 78 2e 61 70 70 } //1 /Library/emp/Spyrix.app
		$a_01_3 = {64 61 73 68 62 6f 61 72 64 2e 73 70 79 72 69 78 2e 63 6f 6d 2f 70 72 67 2d 61 63 74 69 6f 6e 73 } //1 dashboard.spyrix.com/prg-actions
		$a_01_4 = {24 73 31 33 53 70 79 72 69 78 5f 48 65 6c 70 65 72 32 33 5f 41 43 52 65 73 6f 75 72 63 65 49 6e 69 74 50 72 6f 74 6f 63 6f 6c 50 } //1 $s13Spyrix_Helper23_ACResourceInitProtocolP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}