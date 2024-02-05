
rule Trojan_Win32_Priteshel_A{
	meta:
		description = "Trojan:Win32/Priteshel.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00 
		$a_00_1 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //01 00 
		$a_00_2 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //01 00 
		$a_00_3 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}