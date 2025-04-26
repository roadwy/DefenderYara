
rule Trojan_Win32_Delsha_C{
	meta:
		description = "Trojan:Win32/Delsha.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 73 68 61 72 65 20 22 69 70 63 24 22 20 2f 64 65 6c 65 74 65 20 2f 79 } //1 net share "ipc$" /delete /y
		$a_01_1 = {6e 65 74 20 73 68 61 72 65 20 22 61 64 6d 69 6e 24 22 20 2f 64 65 6c 65 74 65 20 2f 79 } //1 net share "admin$" /delete /y
		$a_01_2 = {50 41 54 48 00 00 00 00 2e 63 6f 6d 00 00 00 00 2e 65 78 65 00 00 00 00 2e 62 61 74 } //1
		$a_01_3 = {44 6f 63 73 22 00 00 00 22 4d 79 20 44 6f 63 75 6d 65 6e 74 73 22 00 00 22 70 72 69 6e 74 24 22 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}