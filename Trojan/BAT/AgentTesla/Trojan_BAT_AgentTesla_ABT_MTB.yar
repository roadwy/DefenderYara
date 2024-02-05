
rule Trojan_BAT_AgentTesla_ABT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 53 04 00 00 95 2e 03 16 2b 01 17 7e 08 00 00 04 20 ef 01 00 00 95 5a 7e 08 00 00 04 20 bc 04 00 00 95 58 61 81 07 00 00 01 } //01 00 
		$a_01_1 = {95 2e 03 16 2b 01 17 17 59 7e 1d 00 00 04 20 e7 06 00 00 95 5f 7e 1d 00 00 04 20 ca 0f 00 00 95 61 59 81 07 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}