
rule VirTool_Win32_BofScconfig_A{
	meta:
		description = "VirTool:Win32/BofScconfig.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 4f 46 5f 53 56 43 5f 4e 41 4d 45 } //01 00  BOF_SVC_NAME
		$a_01_1 = {6c 70 63 73 7a 48 6f 73 74 4e 61 6d 65 } //01 00  lpcszHostName
		$a_01_2 = {6c 70 63 73 7a 53 65 72 76 69 63 65 4e 61 6d 65 } //01 00  lpcszServiceName
		$a_01_3 = {63 6f 6e 66 69 67 5f 73 65 72 76 69 63 65 20 66 61 69 6c 65 64 } //01 00  config_service failed
		$a_01_4 = {41 72 67 75 6d 65 6e 74 20 64 6f 6d 61 69 6e 20 } //00 00  Argument domain 
	condition:
		any of ($a_*)
 
}