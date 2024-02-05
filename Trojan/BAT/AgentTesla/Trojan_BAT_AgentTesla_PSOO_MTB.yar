
rule Trojan_BAT_AgentTesla_PSOO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSOO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 00 07 18 6f 90 01 03 0a 00 07 18 6f 90 01 03 0a 00 07 06 6f 90 01 03 0a 00 07 6f 90 01 03 0a 03 16 03 8e 69 6f 90 01 03 0a 0c de 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}