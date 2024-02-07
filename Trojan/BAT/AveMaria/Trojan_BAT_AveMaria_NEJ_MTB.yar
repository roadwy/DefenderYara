
rule Trojan_BAT_AveMaria_NEJ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 5f 36 64 38 37 32 39 35 63 36 32 66 30 35 62 32 30 37 66 31 33 61 30 38 36 66 63 36 30 34 61 31 37 } //05 00  get__6d87295c62f05b207f13a086fc604a17
		$a_01_1 = {67 65 74 5f 62 31 31 36 31 39 63 61 34 64 36 36 63 65 65 62 35 39 63 37 63 35 66 62 38 65 38 65 37 33 38 64 } //02 00  get_b11619ca4d66ceeb59c7c5fb8e8e738d
		$a_01_2 = {49 44 41 54 78 } //02 00  IDATx
		$a_01_3 = {63 65 65 62 35 39 63 37 63 35 66 62 38 65 38 65 37 33 38 64 } //01 00  ceeb59c7c5fb8e8e738d
		$a_01_4 = {45 6d 62 61 6c 6d 65 72 } //01 00  Embalmer
		$a_01_5 = {57 6f 72 64 52 61 63 6b } //00 00  WordRack
	condition:
		any of ($a_*)
 
}