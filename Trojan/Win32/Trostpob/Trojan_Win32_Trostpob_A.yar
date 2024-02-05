
rule Trojan_Win32_Trostpob_A{
	meta:
		description = "Trojan:Win32/Trostpob.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 6c 77 6f 72 67 73 75 77 } //01 00 
		$a_01_1 = {73 69 75 65 75 32 64 6f 77 67 } //01 00 
		$a_01_2 = {61 64 6f 77 68 67 2e 70 68 70 } //01 00 
		$a_01_3 = {73 68 6f 68 65 67 2e 70 68 70 } //01 00 
		$a_01_4 = {67 68 65 6f 77 74 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}