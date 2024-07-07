
rule Trojan_Win32_Popureb_H{
	meta:
		description = "Trojan:Win32/Popureb.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 26 c7 05 4c 00 00 00 06 01 67 26 8c 0d 4e 00 00 00 66 33 db } //1
		$a_01_1 = {68 65 6c 6c 6f 5f 74 74 2e 73 79 73 } //1 hello_tt.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}