
rule Trojan_Win32_Dofoil_AB{
	meta:
		description = "Trojan:Win32/Dofoil.AB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 68 5f 73 77 69 74 68 } //01 00 
		$a_01_1 = {61 75 74 68 5f 6c 6f 67 69 6e } //01 00 
		$a_01_2 = {48 6f 73 74 3a 20 25 73 } //0a 00 
		$a_01_3 = {69 64 6c 65 5f 25 64 } //0a 00 
		$a_01_4 = {65 78 63 65 70 74 69 6f 6e 2f 64 65 74 61 69 6c 2f 65 78 63 65 70 74 69 6f 6e 5f 70 74 72 2e 68 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}