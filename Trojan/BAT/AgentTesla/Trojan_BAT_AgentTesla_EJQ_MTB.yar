
rule Trojan_BAT_AgentTesla_EJQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a de 03 26 de 08 07 17 58 0b 07 03 31 df 90 00 } //01 00 
		$a_01_1 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //01 00  䘀潲䉭獡㙥匴牴湩g
		$a_01_2 = {6d 00 61 00 74 00 65 00 6a 00 70 00 67 00 } //00 00  matejpg
	condition:
		any of ($a_*)
 
}