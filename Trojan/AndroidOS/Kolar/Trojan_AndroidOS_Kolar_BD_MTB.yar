
rule Trojan_AndroidOS_Kolar_BD_MTB{
	meta:
		description = "Trojan:AndroidOS/Kolar.BD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 62 72 61 62 31 36 2e 30 } //01 00  Abrab16.0
		$a_00_1 = {57 6f 64 6b 54 69 76 61 } //01 00  WodkTiva
		$a_00_2 = {61 64 6d 73 75 72 70 72 69 73 65 73 } //01 00  admsurprises
		$a_00_3 = {41 7a 61 62 65 6c 65 72 69 6e 61 } //01 00  Azabelerina
		$a_00_4 = {42 69 65 41 63 74 6f 2e } //00 00  BieActo.
	condition:
		any of ($a_*)
 
}