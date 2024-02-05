
rule Ransom_AndroidOS_Lucy_B{
	meta:
		description = "Ransom:AndroidOS/Lucy.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {67 65 6e 62 6a 33 62 36 30 33 39 32 64 32 32 32 4d 31 61 32 69 6e 33 41 63 74 69 31 76 69 74 79 } //01 00 
		$a_00_1 = {52 65 71 50 65 72 6d 20 61 63 74 69 76 69 6c 69 20 64 6f 77 6e } //01 00 
		$a_00_2 = {67 65 6e 6b 30 6e 67 6e 30 68 30 34 6f 32 32 32 52 31 65 71 32 50 65 33 31 31 72 6d } //00 00 
		$a_00_3 = {5d 04 00 } //00 8b 
	condition:
		any of ($a_*)
 
}