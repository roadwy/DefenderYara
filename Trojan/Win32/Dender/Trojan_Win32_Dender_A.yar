
rule Trojan_Win32_Dender_A{
	meta:
		description = "Trojan:Win32/Dender.A,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2d 00 75 00 3a 00 74 00 20 00 } //0a 00 
		$a_00_1 = {20 00 69 00 63 00 61 00 63 00 6c 00 73 00 20 00 } //0a 00 
		$a_00_2 = {20 00 73 00 6d 00 61 00 72 00 74 00 73 00 63 00 72 00 65 00 65 00 6e 00 2e 00 65 00 78 00 65 00 20 00 } //0a 00 
		$a_00_3 = {72 00 65 00 6d 00 6f 00 76 00 65 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}