
rule Trojan_Win32_Remcos_AD_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6d 6d 64 6c 67 5f 46 69 6e 64 52 65 70 6c 61 63 65 } //commdlg_FindReplace  3
		$a_80_1 = {48 65 6c 70 4b 65 79 77 6f 72 64 } //HelpKeyword  3
		$a_80_2 = {4d 71 79 70 64 78 5c 65 67 63 } //Mqypdx\egc  3
		$a_80_3 = {44 57 45 37 38 50 6d 51 57 5f 62 67 68 67 } //DWE78PmQW_bghg  3
		$a_80_4 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //WinHttpCrackUrl  3
		$a_80_5 = {44 75 63 6b 79 } //Ducky  3
		$a_80_6 = {52 65 61 64 20 49 63 6f 6e 20 4c 69 73 74 20 66 6f 72 20 44 65 6c 70 68 69 20 33 2e 30 } //Read Icon List for Delphi 3.0  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}