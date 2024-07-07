
rule Trojan_Win32_KillFiles_AN_MTB{
	meta:
		description = "Trojan:Win32/KillFiles.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 62 6c 57 69 6e } //1 LblWin
		$a_01_1 = {59 00 6f 00 75 00 27 00 76 00 65 00 20 00 66 00 69 00 6c 00 6c 00 65 00 64 00 20 00 74 00 68 00 65 00 20 00 6c 00 69 00 73 00 74 00 20 00 62 00 6f 00 78 00 2e 00 20 00 41 00 62 00 61 00 6e 00 64 00 6f 00 6e 00 69 00 6e 00 67 00 20 00 73 00 65 00 61 00 72 00 63 00 68 00 } //1 You've filled the list box. Abandoning search
		$a_01_2 = {77 00 69 00 6e 00 2e 00 69 00 6e 00 69 00 } //1 win.ini
		$a_01_3 = {44 69 72 31 5f 43 68 61 6e 67 65 } //1 Dir1_Change
		$a_01_4 = {44 72 69 76 65 31 5f 43 68 61 6e 67 65 } //1 Drive1_Change
		$a_01_5 = {46 69 6c 65 31 5f 43 6c 69 63 6b } //1 File1_Click
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}