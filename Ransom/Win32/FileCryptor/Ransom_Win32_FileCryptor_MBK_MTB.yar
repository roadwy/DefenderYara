
rule Ransom_Win32_FileCryptor_MBK_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 07 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //10 vssadmin.exe delete shadows /all /quiet
		$a_81_1 = {57 4d 49 43 2e 65 78 65 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //10 WMIC.exe shadowcopy delete /nointeractive
		$a_81_2 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //10 bcdedit.exe /set {default} recoveryenabled No
		$a_81_3 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 20 77 62 61 64 6d 69 6e 20 44 45 4c 45 54 45 20 53 59 53 54 45 4d 53 54 41 54 45 42 41 43 4b 55 50 20 77 62 61 64 6d 69 6e 20 44 45 4c 45 54 45 } //10 bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures wbadmin DELETE SYSTEMSTATEBACKUP wbadmin DELETE
		$a_81_4 = {6e 65 74 20 73 74 6f 70 20 42 61 63 6b 75 70 45 78 65 63 41 67 65 6e 74 41 63 63 65 6c 65 72 61 74 6f 72 20 2f 79 } //1 net stop BackupExecAgentAccelerator /y
		$a_81_5 = {6e 65 74 20 73 74 6f 70 20 42 61 63 6b 75 70 45 78 65 63 41 67 65 6e 74 42 72 6f 77 73 65 72 20 2f 79 } //1 net stop BackupExecAgentBrowser /y
		$a_81_6 = {6e 65 74 20 73 74 6f 70 20 4d 63 41 66 65 65 45 6e 67 69 6e 65 53 65 72 76 69 63 65 20 2f 79 } //1 net stop McAfeeEngineService /y
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=31
 
}