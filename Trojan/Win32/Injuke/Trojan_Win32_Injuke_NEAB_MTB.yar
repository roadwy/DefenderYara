
rule Trojan_Win32_Injuke_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Injuke.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 55 6e 69 74 5f 4d 6f 6e 69 74 6f 72 4a 75 6e 6b 46 69 6c 65 73 5f 47 6c 6f 62 61 6c 56 61 72 } //4 $Unit_MonitorJunkFiles_GlobalVar
		$a_01_1 = {55 6e 69 74 5f 46 6f 72 6d 5f 53 79 73 74 65 6d 4a 75 6e 6b 46 69 6c 65 73 5f 4d 6f 6e 69 74 6f 72 } //4 Unit_Form_SystemJunkFiles_Monitor
		$a_01_2 = {4a 75 6e 6b 20 46 69 6c 65 73 20 4d 6f 6e 69 74 6f 72 20 56 31 2e 30 } //4 Junk Files Monitor V1.0
		$a_01_3 = {53 75 62 6d 65 6e 75 5f 4a 75 6e 6b 46 69 6c 65 73 4d 6f 6e 69 74 6f 72 43 6c 69 63 6b } //4 Submenu_JunkFilesMonitorClick
		$a_01_4 = {41 6c 70 63 52 65 67 69 73 74 65 72 43 6f 6d 70 6c 65 74 69 6f 6e 4c 69 73 74 57 6f 72 6b 65 72 54 68 72 65 61 64 } //4 AlpcRegisterCompletionListWorkerThread
		$a_01_5 = {31 00 2e 00 30 00 2e 00 33 00 2e 00 31 00 31 00 38 00 } //2 1.0.3.118
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*2) >=22
 
}