
rule Ransom_MSIL_REVENGE_DB_MTB{
	meta:
		description = "Ransom:MSIL/REVENGE.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 08 5d 0b 03 07 6f 90 01 03 0a 1f 41 59 13 04 06 09 02 09 91 11 04 58 20 00 01 00 00 5d d2 9c 07 17 58 0b 00 09 17 58 0d 09 02 8e 69 fe 04 13 05 11 05 2d ca 90 00 } //01 00 
		$a_81_1 = {47 65 6e 65 72 61 74 65 50 61 73 73 77 6f 72 64 } //01 00 
		$a_81_2 = {65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}