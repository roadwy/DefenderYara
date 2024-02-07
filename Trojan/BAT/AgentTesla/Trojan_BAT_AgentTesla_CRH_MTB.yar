
rule Trojan_BAT_AgentTesla_CRH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 41 32 33 35 34 38 00 } //01 00  䄀㌲㐵8
		$a_01_1 = {00 41 36 35 34 36 00 41 73 73 65 6d 62 6c 79 00 } //01 00  䄀㔶㘴䄀獳浥汢y
		$a_01_2 = {00 41 36 38 37 39 00 } //01 00 
		$a_01_3 = {00 41 41 41 31 32 33 00 } //01 00  䄀䅁㈱3
		$a_01_4 = {00 41 39 32 38 33 00 } //01 00 
		$a_01_5 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_7 = {54 6f 44 6f 75 62 6c 65 } //01 00  ToDouble
		$a_01_8 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_9 = {41 70 70 65 6e 64 } //00 00  Append
	condition:
		any of ($a_*)
 
}