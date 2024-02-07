
rule Trojan_BAT_AgentTesla_DWJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 49 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00 
		$a_01_1 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00  䤀彟彟彟彟I
		$a_01_2 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00 
		$a_01_3 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00  䤀彟彟彟彟彟I
		$a_01_4 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //01 00 
		$a_01_5 = {00 47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 00 } //01 00  䜀瑥硅潰瑲摥祔数s
		$a_01_6 = {00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 } //01 00  䌀敲瑡䥥獮慴据e
		$a_81_7 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_81_8 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}