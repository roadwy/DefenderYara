
rule Trojan_Win32_Killav_F{
	meta:
		description = "Trojan:Win32/Killav.F,SIGNATURE_TYPE_PEHSTR,3f 00 3f 00 0e 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {72 72 6f 72 69 73 74 61 20 6d 6f 72 74 6f 20 6f 6f 6f 6f 6f 6f 20 55 53 48 41 75 75 68 } //10 rrorista morto oooooo USHAuuh
		$a_01_2 = {73 77 66 6c 61 73 68 2e 69 6e 66 } //10 swflash.inf
		$a_01_3 = {46 72 6d 46 72 77 61 6c 6c } //10 FrmFrwall
		$a_01_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //10 SetWindowsHookExA
		$a_01_5 = {46 50 5f 41 58 5f 43 41 42 5f 49 4e 53 54 41 4c 4c 45 52 2e 65 78 65 } //10 FP_AX_CAB_INSTALLER.exe
		$a_01_6 = {61 76 61 73 74 } //1 avast
		$a_01_7 = {6e 6f 64 33 32 } //1 nod32
		$a_01_8 = {6d 63 61 66 65 65 } //1 mcafee
		$a_01_9 = {73 70 79 77 61 72 65 } //1 spyware
		$a_01_10 = {61 76 69 72 61 } //1 avira
		$a_01_11 = {6b 61 73 70 65 72 73 6b 79 } //1 kaspersky
		$a_01_12 = {70 61 6e 64 61 } //1 panda
		$a_01_13 = {73 79 6d 61 6e 74 65 63 } //1 symantec
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=63
 
}