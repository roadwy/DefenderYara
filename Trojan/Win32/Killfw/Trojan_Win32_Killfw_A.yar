
rule Trojan_Win32_Killfw_A{
	meta:
		description = "Trojan:Win32/Killfw.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 73 65 63 75 72 69 74 79 20 63 65 6e 74 65 72 22 20 2f 76 20 46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 34 20 2f 66 } //1 reg add "HKLM\software\microsoft\security center" /v FirewallDisableNotify /t REG_DWORD /d 4 /f
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 73 65 63 75 72 69 74 79 20 63 65 6e 74 65 72 22 20 2f 76 20 55 70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 34 20 2f 66 } //1 reg add "HKLM\software\microsoft\security center" /v UpdatesDisableNotify /t REG_DWORD /d 4 /f
		$a_01_2 = {63 61 6c 6c 20 73 76 73 68 6f 73 74 2e 65 78 65 } //1 call svshost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}