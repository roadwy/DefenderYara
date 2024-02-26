
rule Trojan_BAT_AgentTesla_AMBW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 06 19 5d 28 90 01 01 00 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 32 db 90 00 } //02 00 
		$a_01_1 = {13 17 11 1d 11 09 91 13 20 11 1d 11 09 11 20 11 21 61 19 11 1c 58 61 11 28 61 d2 9c 11 20 13 1c 17 11 09 58 13 09 } //00 00 
	condition:
		any of ($a_*)
 
}