
rule Trojan_BAT_AgentTesla_NUX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 fe 0c 00 00 fe 0c 02 00 91 fe 0c 02 00 28 90 01 03 0a 28 90 01 03 0a 61 d1 fe 0e 03 00 fe 0d 03 00 28 90 01 03 0a 28 90 01 03 0a fe 0e 01 00 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 00 00 8e 69 fe 04 fe 0e 04 00 fe 0c 04 00 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}