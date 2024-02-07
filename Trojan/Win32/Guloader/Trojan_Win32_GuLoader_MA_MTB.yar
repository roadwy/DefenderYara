
rule Trojan_Win32_GuLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 45 00 58 00 45 00 22 00 20 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //03 00  C:\Windows\explorer.EXE" C:\windows\system32\svchost.exe
		$a_81_1 = {55 6e 69 6e 73 74 61 6c 6c 5c 50 44 46 5f 52 65 61 64 65 72 } //03 00  Uninstall\PDF_Reader
		$a_81_2 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 41 28 69 20 72 35 2c 20 69 20 30 2c 20 69 20 30 78 34 30 2c 20 69 20 30 2c 20 69 20 30 2c 20 69 20 30 29 69 2e 72 34 } //03 00  CreateFileMappingA(i r5, i 0, i 0x40, i 0, i 0, i 0)i.r4
		$a_81_3 = {76 62 73 65 64 69 74 2e 74 78 74 } //03 00  vbsedit.txt
		$a_81_4 = {53 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 44 61 63 6c } //03 00  SetSecurityDescriptorDacl
		$a_81_5 = {45 78 65 63 54 6f 4c 6f 67 } //03 00  ExecToLog
		$a_81_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //00 00  ShellExecuteExW
	condition:
		any of ($a_*)
 
}