
rule Trojan_Win32_OfficeAppMshta_A{
	meta:
		description = "Trojan:Win32/OfficeAppMshta.A,SIGNATURE_TYPE_CMDHSTR_EXT,32 00 32 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_1 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 } //10 vbscript
		$a_00_2 = {65 00 78 00 65 00 63 00 75 00 74 00 65 00 } //10 execute
		$a_00_3 = {74 00 65 00 78 00 74 00 72 00 61 00 6e 00 67 00 65 00 } //10 textrange
		$a_00_4 = {77 00 6f 00 72 00 64 00 2e 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //10 word.application
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10) >=50
 
}