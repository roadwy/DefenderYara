
rule Ransom_Win64_Clop_J{
	meta:
		description = "Ransom:Win64/Clop.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 00 2e 00 2a 00 00 00 25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 } //01 00 
		$a_03_1 = {25 00 73 00 5c 00 21 00 90 02 20 5f 00 52 00 45 00 41 00 44 00 5f 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}