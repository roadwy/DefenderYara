
rule Trojan_Win32_BHO_EP{
	meta:
		description = "Trojan:Win32/BHO.EP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 b2 01 a1 90 01 04 e8 90 01 04 33 c0 5a 59 59 64 89 10 eb 90 01 01 e9 90 00 } //01 00 
		$a_00_1 = {79 64 6f 77 6e } //01 00 
		$a_00_2 = {74 70 6f 70 75 70 6c 69 73 74 } //01 00 
		$a_00_3 = {5c 6c 69 76 65 66 6c 6f 61 74 } //01 00 
		$a_00_4 = {5c 5f 69 65 62 72 6f 77 73 65 72 68 65 6c 70 65 72 2e 70 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}