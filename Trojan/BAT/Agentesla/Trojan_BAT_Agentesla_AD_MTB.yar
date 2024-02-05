
rule Trojan_BAT_Agentesla_AD_MTB{
	meta:
		description = "Trojan:BAT/Agentesla.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 28 90 01 02 00 06 7e 0f 00 00 04 6f 90 01 02 00 0a 7e 90 01 02 00 0a 28 90 01 02 00 06 17 6f 90 01 02 00 0a 90 00 } //01 00 
		$a_03_1 = {13 06 11 06 2c 61 1f 0c 8d 90 01 02 00 01 13 0f 11 0f 16 18 9c 11 0f 17 16 9c 11 0f 18 16 9c 11 0f 19 16 9c 11 0f 1a 16 9c 90 00 } //01 00 
		$a_01_2 = {11 0f 1b 16 9c 11 0f 1c 16 9c 11 0f 1d 16 9c 11 0f 1e 16 9c 11 0f 1f 09 16 9c 11 0f 1f 0a 16 9c 11 0f 1f 0b 16 9c 11 0f 13 07 11 06 } //01 00 
		$a_03_3 = {11 0e 11 0d 9a 0d 09 6f 90 01 02 00 0a 6f 90 01 02 00 0a 28 90 01 02 00 0a 0c 08 07 16 28 90 01 02 00 0a 16 33 06 09 6f 90 01 02 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}