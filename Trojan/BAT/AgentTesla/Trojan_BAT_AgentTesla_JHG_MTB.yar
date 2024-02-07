
rule Trojan_BAT_AgentTesla_JHG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {04 94 58 02 7b 07 00 00 04 02 7b 03 00 00 04 94 58 20 00 01 00 00 5d 7d } //0a 00 
		$a_01_1 = {7b 03 00 00 04 91 02 7b 05 00 00 04 61 d2 9c } //01 00 
		$a_81_2 = {54 65 73 74 2d 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  Test-Connection
		$a_81_3 = {70 5e 6f 77 65 5e 72 73 5e 68 65 5e 6c 6c } //01 00  p^owe^rs^he^ll
		$a_81_4 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_5 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}