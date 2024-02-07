
rule Trojan_BAT_AgentTesla_DDY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 52 00 6e 00 52 00 76 00 52 00 6f 00 52 00 6b 00 52 00 65 00 } //01 00  IRnRvRoRkRe
		$a_01_1 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_01_2 = {47 00 2d 00 65 00 2d 00 74 00 2d 00 4d 00 2d 00 65 00 2d 00 74 00 2d 00 68 00 2d 00 6f 00 2d 00 64 00 } //01 00  G-e-t-M-e-t-h-o-d
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_6 = {00 54 6f 44 6f 75 62 6c 65 00 } //01 00  吀䑯畯汢e
		$a_01_7 = {00 49 4f 39 32 31 33 35 37 00 } //01 00  䤀㥏ㄲ㔳7
		$a_01_8 = {00 49 4f 39 32 31 33 36 00 } //01 00 
		$a_01_9 = {00 49 4f 39 32 31 33 33 00 } //00 00 
	condition:
		any of ($a_*)
 
}