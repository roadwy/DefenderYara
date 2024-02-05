
rule Ransom_Win32_Hermes_A_bit{
	meta:
		description = "Ransom:Win32/Hermes.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 74 61 72 74 2e 62 61 74 } //01 00 
		$a_01_1 = {5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 72 75 6e 2e 73 63 74 } //01 00 
		$a_01_2 = {5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 62 00 61 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}