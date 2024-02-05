
rule Trojan_BAT_AgentTesla_FAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 0e 2b 1b 08 11 0e 8f 90 01 01 00 00 01 25 47 07 11 0e 07 8e 69 5d 91 61 d2 52 11 0e 17 58 13 0e 11 0e 08 8e 69 32 de 90 00 } //02 00 
		$a_03_1 = {13 0b 20 00 04 00 00 8d 90 01 01 00 00 01 13 0c 16 13 0d 2b 0c 11 0b 11 0c 16 11 0d 6f 90 01 01 00 00 0a 11 0a 11 0c 16 11 0c 8e 69 6f 90 01 01 00 00 0a 25 13 0d 16 30 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}