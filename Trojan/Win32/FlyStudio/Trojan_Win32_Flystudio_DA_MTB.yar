
rule Trojan_Win32_Flystudio_DA_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 48 52 73 4e 54 59 31 4e 6a 55 31 4e 69 35 31 4d 53 35 73 64 58 6c 76 64 58 68 70 59 53 35 75 5a 58 52 38 4e 54 4d 77 4e 7a 45 3d } //1 aHRsNTY1NjU1Ni51MS5sdXlvdXhpYS5uZXR8NTMwNzE=
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 63 6d 64 2e 65 78 65 } //1 taskkill /im cmd.exe
		$a_81_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 73 76 63 68 63 73 74 2e 65 78 65 } //1 cmd.exe /c del svchcst.exe
		$a_81_3 = {4d 69 63 72 6f 73 6f 66 74 5c 73 76 63 68 63 73 74 2e 65 78 65 } //1 Microsoft\svchcst.exe
		$a_03_4 = {4d 69 63 72 6f 73 6f 66 74 5c [0-0f] 2e 62 61 74 } //1
		$a_03_5 = {5c 53 74 61 72 74 75 70 5c [0-0f] 2e 6c 6e 6b } //1
		$a_81_6 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}