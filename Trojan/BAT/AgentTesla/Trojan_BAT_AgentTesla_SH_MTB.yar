
rule Trojan_BAT_AgentTesla_SH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 57 00 00 0a 72 ed 06 00 70 6f 58 00 00 0a 11 04 1f 16 5d 91 61 13 09 11 09 07 11 04 17 58 09 5d 91 59 20 00 01 00 00 58 13 0a 07 11 08 11 0a 20 00 01 00 00 5d d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}