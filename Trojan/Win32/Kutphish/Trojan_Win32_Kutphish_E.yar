
rule Trojan_Win32_Kutphish_E{
	meta:
		description = "Trojan:Win32/Kutphish.E,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 2d 00 79 00 20 00 90 00 } //1
		$a_02_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 2f 00 79 00 20 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}