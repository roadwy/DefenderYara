
rule Trojan_Win32_Killfiles_EE{
	meta:
		description = "Trojan:Win32/Killfiles.EE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 2a 2e 2a 20 2f 51 20 2f 53 00 63 6c 73 00 } //01 00 
		$a_01_1 = {53 74 61 72 74 69 6e 67 20 4e 65 65 64 20 46 6f 72 20 53 70 65 65 64 3a 20 52 69 76 61 6c 73 2e 2e 2e 00 63 64 2e 2e 00 } //01 00 
		$a_01_2 = {0f 94 c0 84 c0 75 c8 b8 00 00 00 00 c9 c3 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}