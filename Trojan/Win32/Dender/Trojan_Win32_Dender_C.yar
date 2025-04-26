
rule Trojan_Win32_Dender_C{
	meta:
		description = "Trojan:Win32/Dender.C,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 75 00 3a 00 74 00 20 00 } //10 -u:t 
		$a_00_1 = {20 00 72 00 65 00 67 00 20 00 } //10  reg 
		$a_00_2 = {20 00 6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5f 00 73 00 75 00 70 00 70 00 72 00 65 00 73 00 73 00 20 00 } //10  notification_suppress 
		$a_00_3 = {20 00 75 00 78 00 20 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 } //10  ux configuration 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}