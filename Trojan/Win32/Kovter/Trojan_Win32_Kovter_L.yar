
rule Trojan_Win32_Kovter_L{
	meta:
		description = "Trojan:Win32/Kovter.L,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 [0-10] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-ff] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //1
		$a_02_1 = {6d 00 73 00 68 00 74 00 61 00 [0-10] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-ff] 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 [0-ff] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}