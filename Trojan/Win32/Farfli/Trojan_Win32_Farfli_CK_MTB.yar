
rule Trojan_Win32_Farfli_CK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 72 75 6e 64 6c 6c 33 32 32 32 2e 65 78 65 } //1 C:\ProgramData\rundll3222.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 30 37 2e 31 35 31 2e 39 34 2e 37 30 } //1 http://107.151.94.70
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 76 63 68 6f 73 74 2e 74 78 74 } //1 C:\ProgramData\svchost.txt
		$a_01_3 = {6f 6a 62 6b 63 67 2e 65 78 65 } //1 ojbkcg.exe
		$a_01_4 = {65 3a 5c 76 73 5c 6c 75 6a 6b 5c 52 65 6c 65 61 73 65 5c 6c 75 6a 6b 2e 70 64 62 } //1 e:\vs\lujk\Release\lujk.pdb
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}