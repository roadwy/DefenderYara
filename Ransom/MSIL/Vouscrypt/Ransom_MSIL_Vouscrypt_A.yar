
rule Ransom_MSIL_Vouscrypt_A{
	meta:
		description = "Ransom:MSIL/Vouscrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 59 6f 75 72 52 61 6e 73 6f 6d 2f 6d 61 69 6e 2e 67 6f } //01 00 
		$a_00_1 = {2f 59 6f 75 72 52 61 6e 73 6f 6d 2f 66 75 6e 63 73 2e 67 6f } //01 00 
		$a_03_2 = {3b 61 08 0f 86 12 03 00 00 83 ec 54 8b 05 90 01 04 8b 0d 90 01 04 8d 50 01 8b 5c 24 5c 39 d3 0f 8c e9 02 00 00 90 00 } //01 00 
		$a_00_3 = {59 52 30 78 30 32 2e 6b 65 79 } //01 00 
		$a_00_4 = {22 4a 75 73 74 20 73 6d 69 6c 65 20 3a 29 } //01 00 
		$a_00_5 = {22 45 6e 63 53 75 66 66 69 78 22 3a } //00 00 
		$a_00_6 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}