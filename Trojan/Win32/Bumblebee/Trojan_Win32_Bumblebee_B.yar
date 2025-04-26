
rule Trojan_Win32_Bumblebee_B{
	meta:
		description = "Trojan:Win32/Bumblebee.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6f 00 64 00 62 00 63 00 63 00 6f 00 6e 00 66 00 } //1 odbcconf
		$a_00_1 = {72 00 65 00 67 00 73 00 76 00 72 00 } //1 regsvr
		$a_00_2 = {20 00 2f 00 61 00 20 00 } //1  /a 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}