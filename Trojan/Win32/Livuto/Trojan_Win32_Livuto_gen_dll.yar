
rule Trojan_Win32_Livuto_gen_dll{
	meta:
		description = "Trojan:Win32/Livuto.gen!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 16 68 01 95 00 00 68 01 95 00 00 68 01 95 00 00 50 ff 15 } //02 00 
		$a_01_1 = {68 00 03 00 00 51 68 2c 0c 0b 83 56 ff 15 } //01 00 
		$a_00_2 = {61 75 74 6f 4c 69 76 65 2e 69 6e 69 00 } //01 00 
		$a_00_3 = {61 75 74 6f 6c 69 76 65 64 6c 6c 2e 63 61 62 00 } //01 00 
		$a_00_4 = {75 70 64 61 74 65 25 64 2e 63 61 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}