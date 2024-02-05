
rule Trojan_BAT_AgentTesla_AIIW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AIIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {a2 25 17 07 a2 25 0c 14 14 18 8d a2 00 00 01 25 17 17 9c 25 0d 17 28 } //01 00 
		$a_01_1 = {52 00 65 00 6e 00 74 00 61 00 6c 00 2e 00 44 00 61 00 74 00 61 00 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}