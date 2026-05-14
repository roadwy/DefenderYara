
rule Trojan_Win32_DiskWriter_SX_MTB{
	meta:
		description = "Trojan:Win32/DiskWriter.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,36 00 36 00 06 00 00 "
		
	strings :
		$a_03_0 = {99 b9 14 00 00 00 f7 f9 83 ea 0a 89 55 ?? ?? ?? ?? ?? ?? 99 b9 14 00 00 00 f7 f9 83 ea 0a } //20
		$a_03_1 = {c1 ea 08 8b 45 ?? c1 e8 09 0b d0 0f af 55 ?? 83 e2 2e 8b 4d ?? c1 e9 08 23 d1 } //15
		$a_01_2 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 20 2f 76 20 53 68 65 6c 6c 20 2f 64 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //10 reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Shell /d explorer.exe
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 73 76 63 68 6f 73 74 2e 65 78 65 20 3e 6e 75 6c 20 32 3e 26 31 } //5 taskkill /f /im svchost.exe >nul 2>&1
		$a_01_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //2 \\.\PhysicalDrive0
		$a_01_5 = {62 6f 6f 74 2e 62 69 6e } //2 boot.bin
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=54
 
}