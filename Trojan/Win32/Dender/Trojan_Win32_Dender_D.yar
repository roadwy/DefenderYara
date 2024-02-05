
rule Trojan_Win32_Dender_D{
	meta:
		description = "Trojan:Win32/Dender.D,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 20 00 } //0a 00 
		$a_00_1 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 } //0a 00 
		$a_00_2 = {62 00 79 00 70 00 61 00 73 00 73 00 2d 00 74 00 61 00 6d 00 70 00 65 00 72 00 2d 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}