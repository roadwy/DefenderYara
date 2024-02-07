
rule Trojan_BAT_AgentTesla_CNV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 d8 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 90 00 } //01 00 
		$a_01_1 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_01_2 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_01_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {50 61 72 61 6d 58 41 72 72 61 79 } //00 00  ParamXArray
	condition:
		any of ($a_*)
 
}