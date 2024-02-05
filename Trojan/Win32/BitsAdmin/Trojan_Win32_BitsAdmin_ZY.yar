
rule Trojan_Win32_BitsAdmin_ZY{
	meta:
		description = "Trojan:Win32/BitsAdmin.ZY,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 } //05 00 
		$a_00_1 = {2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //01 00 
		$a_02_2 = {24 00 5c 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_02_3 = {24 00 5c 00 90 02 30 2e 00 64 00 6c 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}