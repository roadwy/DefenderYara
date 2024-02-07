
rule Trojan_BAT_Njrat_ABY_MTB{
	meta:
		description = "Trojan:BAT/Njrat.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 11 05 02 11 05 91 11 04 61 09 08 91 61 b4 9c 08 03 6f 0d 00 00 0a 17 da fe 01 13 07 11 07 2c 04 16 0c 2b 05 00 08 17 d6 0c 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c5 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {6f 00 61 00 6e 00 73 00 65 00 65 00 65 00 65 00 65 00 65 00 } //01 00  oanseeeeee
		$a_01_3 = {7a 00 77 00 6f 00 61 00 61 00 61 00 65 00 65 00 65 00 65 00 65 00 } //00 00  zwoaaaeeeee
	condition:
		any of ($a_*)
 
}