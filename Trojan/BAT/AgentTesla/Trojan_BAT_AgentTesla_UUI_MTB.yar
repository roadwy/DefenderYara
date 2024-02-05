
rule Trojan_BAT_AgentTesla_UUI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 28 90 01 03 06 07 20 ff 00 00 00 5d 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {46 42 36 34 53 } //00 00 
	condition:
		any of ($a_*)
 
}