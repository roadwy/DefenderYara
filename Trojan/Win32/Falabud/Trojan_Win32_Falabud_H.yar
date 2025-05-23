
rule Trojan_Win32_Falabud_H{
	meta:
		description = "Trojan:Win32/Falabud.H,SIGNATURE_TYPE_CMDHSTR_EXT,5a 00 5a 00 09 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_1 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 } //10 vbscript
		$a_00_2 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 } //10 wscript
		$a_00_3 = {73 00 68 00 65 00 6c 00 6c 00 } //10 shell
		$a_00_4 = {72 00 75 00 6e 00 } //10 run
		$a_00_5 = {66 00 6f 00 72 00 } //10 for
		$a_00_6 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //10 msiexec
		$a_00_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //10 http://
		$a_00_8 = {77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 63 00 6c 00 6f 00 73 00 65 00 } //10 window.close
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10) >=90
 
}