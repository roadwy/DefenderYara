
rule Trojan_Win32_Zbot_DSK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 78 00 59 00 70 00 57 00 44 00 33 00 46 00 74 00 2e 00 65 00 78 00 65 00 } //1 C:\xYpWD3Ft.exe
		$a_01_1 = {43 00 3a 00 5c 00 7a 00 72 00 73 00 75 00 32 00 6a 00 4b 00 5a 00 2e 00 65 00 78 00 65 00 } //1 C:\zrsu2jKZ.exe
		$a_01_2 = {43 00 3a 00 5c 00 56 00 34 00 71 00 6f 00 6f 00 56 00 6e 00 4a 00 2e 00 65 00 78 00 65 00 } //1 C:\V4qooVnJ.exe
		$a_01_3 = {43 00 3a 00 5c 00 5a 00 4c 00 55 00 54 00 53 00 61 00 6f 00 46 00 2e 00 65 00 78 00 65 00 } //1 C:\ZLUTSaoF.exe
		$a_01_4 = {43 00 3a 00 5c 00 72 00 63 00 76 00 73 00 65 00 35 00 63 00 77 00 2e 00 65 00 78 00 65 00 } //1 C:\rcvse5cw.exe
		$a_01_5 = {43 00 3a 00 5c 00 45 00 74 00 79 00 49 00 33 00 6b 00 37 00 49 00 2e 00 65 00 78 00 65 00 } //1 C:\EtyI3k7I.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}