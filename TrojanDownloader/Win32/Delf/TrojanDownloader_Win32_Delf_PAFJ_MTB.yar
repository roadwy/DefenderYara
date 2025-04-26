
rule TrojanDownloader_Win32_Delf_PAFJ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Delf.PAFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 2e 65 78 65 } //1 processhacker.exe
		$a_01_1 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskmgr.exe
		$a_01_2 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2f 73 } //1 regsvr32.exe /s
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 56 4d 77 61 72 65 2c 20 49 6e 63 2e 5c 56 4d 77 61 72 65 20 54 6f 6f 6c 73 } //1 SOFTWARE\VMware, Inc.\VMware Tools
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4f 72 61 63 6c 65 5c 56 69 72 74 75 61 6c 42 6f 78 20 47 75 65 73 74 20 41 64 64 69 74 69 6f 6e 73 } //1 SOFTWARE\Oracle\VirtualBox Guest Additions
		$a_01_5 = {3a 2f 2f 25 73 2f 67 61 74 65 2f 64 6f 77 6e 6c 6f 61 64 5f 65 78 65 63 } //1 ://%s/gate/download_exec
		$a_01_6 = {3a 2f 2f 25 73 2f 67 61 74 65 2f 75 70 64 61 74 65 5f 65 78 65 63 } //1 ://%s/gate/update_exec
		$a_01_7 = {70 72 6f 63 65 78 70 2e 65 78 65 } //1 procexp.exe
		$a_01_8 = {70 72 6f 63 6d 6f 6e 2e 65 78 65 } //1 procmon.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}