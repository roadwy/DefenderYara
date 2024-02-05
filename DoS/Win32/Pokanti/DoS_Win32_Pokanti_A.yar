
rule DoS_Win32_Pokanti_A{
	meta:
		description = "DoS:Win32/Pokanti.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 6e 00 74 00 69 00 20 00 50 00 6f 00 72 00 6e 00 6f 00 67 00 72 00 61 00 66 00 69 00 } //01 00 
		$a_01_1 = {7e 00 20 00 49 00 4e 00 44 00 4f 00 4e 00 45 00 53 00 49 00 41 00 4e 00 20 00 56 00 58 00 20 00 5a 00 4f 00 4e 00 45 00 20 00 7e 00 } //01 00 
		$a_01_2 = {56 69 72 42 6f 6b 33 70 } //00 00 
	condition:
		any of ($a_*)
 
}