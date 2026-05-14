
rule HackTool_Win32_WinActivator_MTB{
	meta:
		description = "HackTool:Win32/WinActivator!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 20 57 69 6e 64 6f 77 73 20 72 65 61 63 74 69 76 61 74 69 6f 6e 20 74 61 73 6b } //1 Create Windows reactivation task
		$a_01_1 = {43 72 65 61 74 65 20 4f 66 66 69 63 65 20 72 65 61 63 74 69 76 61 74 69 6f 6e 20 74 61 73 6b } //1 Create Office reactivation task
		$a_01_2 = {49 6e 73 74 61 6c 6c 20 47 56 4c 4b 20 4b 65 79 } //1 Install GVLK Key
		$a_00_3 = {41 00 41 00 63 00 74 00 5f 00 66 00 69 00 6c 00 65 00 73 00 5c 00 4b 00 4d 00 53 00 53 00 53 00 2e 00 65 00 78 00 65 00 } //1 AAct_files\KMSSS.exe
		$a_00_4 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 4b 00 65 00 79 00 } //1 Install Windows Product Key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule HackTool_Win32_WinActivator_MTB_2{
	meta:
		description = "HackTool:Win32/WinActivator!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 72 00 65 00 61 00 63 00 74 00 69 00 76 00 61 00 74 00 69 00 6f 00 6e 00 20 00 74 00 61 00 73 00 6b 00 } //1 Delete Office reactivation task
		$a_01_1 = {55 00 73 00 65 00 20 00 65 00 78 00 74 00 65 00 72 00 6e 00 61 00 6c 00 20 00 4b 00 4d 00 53 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 Use external KMS-Service
		$a_01_2 = {53 00 70 00 70 00 45 00 78 00 74 00 43 00 6f 00 6d 00 4f 00 62 00 6a 00 } //1 SppExtComObj
		$a_01_3 = {5c 00 73 00 6c 00 6d 00 67 00 72 00 2e 00 76 00 62 00 73 00 20 00 2f 00 2f 00 4e 00 6f 00 4c 00 6f 00 67 00 6f 00 20 00 2f 00 63 00 6b 00 6d 00 73 00 } //1 \slmgr.vbs //NoLogo /ckms
		$a_01_4 = {57 00 4e 00 65 00 74 00 41 00 64 00 64 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 32 00 41 00 } //1 WNetAddConnection2A
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}