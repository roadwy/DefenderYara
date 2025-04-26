
rule Trojan_Win32_Dender_B{
	meta:
		description = "Trojan:Win32/Dender.B,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 75 00 3a 00 74 00 20 00 } //10 -u:t 
		$a_00_1 = {20 00 73 00 63 00 20 00 } //10  sc 
		$a_00_2 = {20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 } //10  delete 
		$a_00_3 = {20 00 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 20 00 } //10  windefend 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}