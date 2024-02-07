
rule Trojan_BAT_Remcos_AIGF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AIGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 17 13 04 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 00 09 17 58 90 00 } //01 00 
		$a_01_1 = {43 00 68 00 65 00 73 00 73 00 } //01 00  Chess
		$a_01_2 = {43 00 61 00 72 00 67 00 6f 00 57 00 69 00 73 00 65 00 2e 00 57 00 68 00 69 00 74 00 65 00 } //01 00  CargoWise.White
		$a_01_3 = {53 61 6e 66 6f 72 64 31 30 31 } //01 00  Sanford101
		$a_01_4 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}