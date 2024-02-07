
rule Trojan_Win32_AccessibilityEscalation_GR_MSR{
	meta:
		description = "Trojan:Win32/AccessibilityEscalation.GR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 76 20 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //02 00  /v ShowSuperHidden /t REG_DWORD /d 0 /f
		$a_01_1 = {49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 73 65 74 68 63 2e 65 78 65 22 20 2f 76 20 44 65 62 75 67 67 65 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 6d 67 72 2e 65 78 65 22 20 2f 66 } //00 00  Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\taskmgr.exe" /f
	condition:
		any of ($a_*)
 
}