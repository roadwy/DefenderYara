
rule Trojan_BAT_AgentTesla_MBEW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 11 11 5d 13 13 06 11 17 5d 13 1a 06 17 58 11 11 5d 13 1b 11 0b 11 13 91 13 1c 20 00 01 00 00 13 14 11 1c 11 12 11 1a 91 61 11 0b 11 1b 91 59 11 14 58 11 14 5d 13 1d 11 0b 11 13 11 1d d2 9c 06 17 58 0a 06 11 11 11 16 17 58 5a fe 04 13 1e 11 1e 2d ac } //00 00 
	condition:
		any of ($a_*)
 
}