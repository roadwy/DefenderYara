
rule Trojan_BAT_AgentTesla_AMAO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0c 14 fe 90 01 02 00 00 06 73 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 06 75 90 01 01 00 00 1b 73 90 01 01 00 00 0a 0d 09 07 16 73 90 01 01 00 00 0a 13 04 11 04 08 6f 90 01 01 00 00 0a 7e 90 01 01 00 00 04 08 6f 90 01 01 00 00 0a 14 6f 90 01 01 00 00 0a dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}