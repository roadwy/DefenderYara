
rule Trojan_BAT_AgentTesla_PTID_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PTID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {d0 09 00 00 01 28 90 01 01 00 00 0a 11 06 72 37 00 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 26 20 05 00 00 00 fe 0e 01 00 38 c8 fc ff ff 11 07 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 13 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}