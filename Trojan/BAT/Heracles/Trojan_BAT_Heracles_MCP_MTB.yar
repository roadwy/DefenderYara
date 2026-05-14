
rule Trojan_BAT_Heracles_MCP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 74 75 36 4a 42 51 66 30 4a 6d 6d 49 66 4b 44 5a 47 45 } //1 btu6JBQf0JmmIfKDZGE
		$a_01_1 = {76 43 56 56 74 6e 4a 51 4c 6d 6b 48 4f 65 45 56 51 55 } //1 vCVVtnJQLmkHOeEVQU
		$a_01_2 = {32 62 30 61 33 30 32 31 65 30 37 32 } //1 2b0a3021e072
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}