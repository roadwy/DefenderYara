
rule Trojan_BAT_AgentTesla_PSVC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 07 28 e7 00 00 06 17 73 66 00 00 0a 0c 08 02 16 02 8e 69 28 90 01 01 00 00 06 08 28 90 01 01 00 00 06 06 28 90 01 01 00 00 06 0d 28 90 01 01 00 00 06 09 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}