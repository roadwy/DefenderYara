
rule Trojan_Win32_BitsAdmin_ZZ{
	meta:
		description = "Trojan:Win32/BitsAdmin.ZZ,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 } //01 00  bitsadmin
		$a_00_1 = {2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //01 00  /transfer
		$a_00_2 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //01 00  /download
		$a_00_3 = {2f 00 70 00 72 00 69 00 6f 00 72 00 69 00 74 00 79 00 } //01 00  /priority
		$a_02_4 = {5c 00 63 00 24 00 5c 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_02_5 = {5c 00 63 00 24 00 5c 00 90 02 30 2e 00 64 00 6c 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}