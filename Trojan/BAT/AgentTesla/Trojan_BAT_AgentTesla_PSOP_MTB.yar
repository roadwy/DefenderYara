
rule Trojan_BAT_AgentTesla_PSOP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 06 7b 7e 00 00 04 2d 11 20 65 28 e2 0f 28 90 01 03 2b 28 90 01 03 06 2b 01 17 6f 90 01 03 06 20 20 3b ae 53 38 e8 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}