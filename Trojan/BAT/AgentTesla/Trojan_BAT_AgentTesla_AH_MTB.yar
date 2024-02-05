
rule Trojan_BAT_AgentTesla_AH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 9a 1f 29 95 7e 21 00 00 04 1c 9a 1f 2d 95 60 7e 21 00 00 04 1c 9a 07 0a 20 54 01 00 00 95 61 7e 21 00 00 04 1c 07 0b 9a 20 e1 00 00 00 95 2e 03 16 2b 01 } //02 00 
		$a_01_1 = {17 9a 20 7c 07 00 00 95 2e 03 16 2b 01 17 17 59 7e 21 00 00 04 17 9a 20 08 07 00 00 95 5f 7e 21 00 00 04 17 9a 20 36 0a 00 00 95 61 58 80 20 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}