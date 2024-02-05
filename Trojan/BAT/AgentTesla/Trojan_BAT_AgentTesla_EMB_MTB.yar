
rule Trojan_BAT_AgentTesla_EMB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 7e 90 01 03 04 28 90 01 03 06 18 58 19 59 fe 01 13 06 11 06 39 90 01 04 16 0d 38 90 01 04 09 17 58 0d 00 11 04 17 58 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}