
rule Trojan_Win32_Fragtor_NK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_03_0 = {c1 c8 02 33 d0 8b 45 ?? 8b c8 23 45 ?? 0b 4d ?? 23 4d ?? 0b c8 8b 45 ?? 03 c6 03 ca 03 ce 89 45 ?? 8b f0 89 4d ?? c1 c0 07 } //2
		$a_01_1 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa } //2
		$a_02_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 [0-20] 4d 00 75 00 74 00 65 00 78 00 } //2
		$a_02_3 = {47 6c 6f 62 61 6c 5c [0-20] 4d 75 74 65 78 } //2
		$a_81_4 = {2f 63 20 53 43 48 54 41 53 4b 53 2e 65 78 65 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 42 45 54 41 22 20 2f 46 } //1 /c SCHTASKS.exe /Delete /TN "Windows Update BETA" /F
		$a_81_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_81_6 = {44 65 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 64 } //1 Decryption Completed
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=9
 
}