
rule Trojan_BAT_AgentTesla_ASET_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 90 01 01 02 00 0a 0b 02 28 90 01 01 05 00 06 75 90 01 01 00 00 1b 73 90 01 01 02 00 0a 0c 08 11 04 16 73 90 01 01 02 00 0a 0d 09 07 6f 90 01 01 02 00 0a 07 13 05 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}