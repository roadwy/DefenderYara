
rule Trojan_BAT_AgentTesla_DLO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 00 02 11 02 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 90 00 } //01 00 
		$a_01_1 = {02 02 8e 69 17 59 91 1f 70 61 13 01 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {00 47 65 74 54 79 70 65 73 00 } //01 00  䜀瑥祔数s
		$a_01_4 = {00 47 65 74 4d 65 74 68 6f 64 73 00 } //00 00  䜀瑥敍桴摯s
	condition:
		any of ($a_*)
 
}