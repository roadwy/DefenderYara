
rule Trojan_Win32_Dishigy_B{
	meta:
		description = "Trojan:Win32/Dishigy.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 37 2e 20 37 37 2e 20 2e 37 2e 20 38 2e 31 2e } //01 00 
		$a_01_1 = {5c 6b 65 79 73 2e 69 6e 69 } //01 00 
		$a_01_2 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c } //01 00 
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 } //00 00 
	condition:
		any of ($a_*)
 
}