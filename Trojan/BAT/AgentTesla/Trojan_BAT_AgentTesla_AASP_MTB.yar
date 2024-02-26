
rule Trojan_BAT_AgentTesla_AASP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 0d 11 15 5d 13 16 11 0d 11 18 5d 13 1c 11 0e 11 16 91 13 1d 11 14 11 1c 6f 90 01 01 00 00 0a 13 1e 02 11 0e 11 0d 28 90 01 01 00 00 06 13 1f 02 11 1d 11 1e 11 1f 28 90 01 01 00 00 06 13 20 11 0e 11 16 11 20 20 00 01 00 00 5d d2 9c 11 0d 17 59 13 0d 11 0d 16 fe 04 16 fe 01 13 21 11 21 2d a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}