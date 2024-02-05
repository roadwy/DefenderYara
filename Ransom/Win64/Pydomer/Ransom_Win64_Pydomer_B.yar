
rule Ransom_Win64_Pydomer_B{
	meta:
		description = "Ransom:Win64/Pydomer.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 da b5 5a 4d 6c 1b 49 76 ee 6e fe 8a 92 65 d9 e3 91 6c 8f 67 46 33 3b e3 1d cd ce c8 14 25 79 2d af c7 bb 22 25 52 d4 0f 25 91 12 29 36 3c cb } //00 00 
	condition:
		any of ($a_*)
 
}