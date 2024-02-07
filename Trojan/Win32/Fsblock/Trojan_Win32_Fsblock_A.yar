
rule Trojan_Win32_Fsblock_A{
	meta:
		description = "Trojan:Win32/Fsblock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 49 54 42 54 4e 31 5f 42 49 54 4d 41 50 } //01 00  BITBTN1_BITMAP
		$a_01_1 = {e1 eb ee ea e8 f0 ee e2 } //01 00 
		$a_03_2 = {6f 70 3d cc d2 d1 3b 90 01 02 3b 6e 75 6d 3d 90 00 } //00 00 
		$a_00_3 = {78 75 } //00 00  xu
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fsblock_A_2{
	meta:
		description = "Trojan:Win32/Fsblock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {e1 eb ee ea e8 f0 ee e2 } //01 00 
		$a_01_1 = {74 61 73 6b 6d 67 72 2e 65 78 65 2c 20 6d 73 63 6f 6e 66 69 67 2e 65 78 65 2c 20 72 65 67 65 64 69 74 2e 65 78 65 2c 20 63 6d 64 2e 65 78 65 } //01 00  taskmgr.exe, msconfig.exe, regedit.exe, cmd.exe
		$a_03_2 = {70 69 6e 67 20 20 31 32 37 2e 30 2e 30 2e 31 90 02 0a 64 65 6c 90 02 10 64 65 6c 20 25 30 90 02 05 2e 62 61 74 90 00 } //00 00 
		$a_00_3 = {78 98 } //01 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fsblock_A_3{
	meta:
		description = "Trojan:Win32/Fsblock.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 61 73 6b 6d 67 72 2e 65 78 65 2c 20 6d 73 63 6f 6e 66 69 67 2e 65 78 65 2c 20 72 65 67 65 64 69 74 2e 65 78 65 2c 20 63 6d 64 2e 65 78 65 } //01 00  taskmgr.exe, msconfig.exe, regedit.exe, cmd.exe
		$a_02_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 4f 6c 65 20 44 42 5c 90 02 08 2e 65 78 65 90 00 } //01 00 
		$a_00_2 = {52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 } //02 00  REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v
		$a_00_3 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 20 2f 64 20 31 20 2d 79 } //02 00  reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t reg_dword /d 1 -y
		$a_02_4 = {63 6f 70 79 20 90 02 08 2e 65 78 65 20 22 25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 90 02 08 2e 65 78 65 22 20 2d 79 90 00 } //01 00 
		$a_01_5 = {6d 72 62 65 6c 79 61 73 68 6e 6f 00 } //00 00  牭敢祬獡湨o
	condition:
		any of ($a_*)
 
}