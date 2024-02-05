
rule Ransom_Win32_Trigona_A{
	meta:
		description = "Ransom:Win32/Trigona.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 21 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 } //01 00 
		$a_01_1 = {2f 00 74 00 65 00 73 00 74 00 5f 00 63 00 69 00 64 00 } //01 00 
		$a_01_2 = {2f 00 74 00 65 00 73 00 74 00 5f 00 76 00 69 00 64 00 } //01 00 
		$a_01_3 = {2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5f 00 6f 00 6e 00 6c 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}