
rule Trojan_Win32_KillMBR_NM_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 69 7a 68 69 2e 62 6d 70 } //2 bizhi.bmp
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //2 Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr
		$a_01_2 = {5f 45 4c 5f 48 69 64 65 4f 77 6e 65 72 } //1 _EL_HideOwner
		$a_01_3 = {73 74 61 72 74 2d 61 61 71 61 } //1 start-aaqa
		$a_01_4 = {72 61 6e 73 6f 6d } //1 ransom
		$a_01_5 = {62 79 20 7a 75 6f 6c 75 6f } //1 by zuoluo
		$a_01_6 = {79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 76 65 20 61 20 6c 6f 63 6b } //1 your computer have a lock
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}
rule Trojan_Win32_KillMBR_NM_MTB_2{
	meta:
		description = "Trojan:Win32/KillMBR.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {7a 00 69 00 72 00 63 00 6f 00 6e 00 69 00 75 00 6d 00 20 00 74 00 68 00 65 00 20 00 76 00 69 00 72 00 75 00 73 00 20 00 77 00 61 00 6e 00 74 00 73 00 20 00 79 00 6f 00 75 00 72 00 20 00 70 00 63 00 } //2 zirconium the virus wants your pc
		$a_01_1 = {59 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 74 00 6f 00 20 00 72 00 75 00 6e 00 20 00 61 00 20 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 6e 00 61 00 6d 00 65 00 64 00 20 00 5a 00 69 00 72 00 63 00 6f 00 6e 00 69 00 75 00 6d 00 2e 00 65 00 78 00 65 00 } //2 You have to run a malware named Zirconium.exe
		$a_01_2 = {66 00 72 00 65 00 65 00 20 00 6c 00 69 00 66 00 65 00 20 00 68 00 61 00 63 00 6b 00 73 00 20 00 6e 00 6f 00 20 00 66 00 61 00 6b 00 65 00 21 00 21 00 31 00 31 00 } //2 free life hacks no fake!!11
		$a_01_3 = {69 00 66 00 20 00 79 00 6f 00 75 00 20 00 64 00 6f 00 6e 00 74 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 64 00 65 00 73 00 74 00 72 00 6f 00 79 00 20 00 79 00 6f 00 75 00 72 00 20 00 70 00 63 00 20 00 50 00 52 00 45 00 53 00 53 00 20 00 4e 00 4f 00 20 00 41 00 4e 00 44 00 20 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 49 00 54 00 20 00 46 00 41 00 53 00 54 00 4c 00 59 00 21 00 } //1 if you dont want to destroy your pc PRESS NO AND DELETE IT FASTLY!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}