
rule Ransom_MSIL_Hyptkript_A_{
	meta:
		description = "Ransom:MSIL/Hyptkript.A!!Hyptkript.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 77 00 61 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //01 00  Your Files was encrypted!
		$a_00_1 = {44 00 6f 00 20 00 79 00 6f 00 75 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 } //02 00  Do you decrypt your Files
		$a_80_2 = {31 34 36 33 34 35 33 35 33 36 5f 76 6f 64 61 66 6f 6e 65 } //1463453536_vodafone  05 00 
	condition:
		any of ($a_*)
 
}