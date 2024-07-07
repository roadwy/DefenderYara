
rule Trojan_Win32_Fragtor_M_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.M!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 45 47 20 41 44 44 20 68 6b 63 75 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 73 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 } //1 REG ADD hkcu\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableTaskMgr /t reg_dword
		$a_01_1 = {64 65 6c 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 68 61 6c 2e 64 6c 6c } //1 del C:\WINDOWS\system32\hal.dll
		$a_01_2 = {50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //1 PhysicalDrive0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}