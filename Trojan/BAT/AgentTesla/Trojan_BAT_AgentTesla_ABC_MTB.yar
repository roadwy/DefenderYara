
rule Trojan_BAT_AgentTesla_ABC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {13 04 5a 58 9e 11 08 7e 90 01 03 04 59 7e 90 01 03 04 20 aa 04 00 00 95 7e 90 01 03 04 7e 90 01 03 04 20 cd 01 00 00 95 61 11 08 58 7e 90 01 03 04 20 4f 0a 00 00 95 5f 5a 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}