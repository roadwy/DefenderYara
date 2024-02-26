
rule Trojan_BAT_AgentTesla_AMAZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 17 d2 13 2e 11 17 1e 63 d1 13 17 11 15 11 0b 91 13 22 11 15 11 0b 11 23 11 22 61 19 11 20 58 61 11 2e 61 d2 9c 11 0b 17 58 13 0b 11 22 13 20 11 0b 11 27 32 a4 } //02 00 
		$a_01_1 = {11 25 11 14 11 0d 11 14 91 9d 11 14 17 58 13 14 11 14 11 1b 32 ea } //00 00 
	condition:
		any of ($a_*)
 
}