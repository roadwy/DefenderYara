
rule Trojan_BAT_AgentTesla_ASBM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 90 01 01 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 01 00 00 06 03 08 90 00 } //02 00 
		$a_01_1 = {8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f } //01 00 
		$a_03_2 = {0f 01 03 8e 69 17 59 16 2c 1f 26 26 03 2a 0a 38 90 01 01 ff ff ff 0b 38 90 01 01 ff ff ff 0c 38 90 01 01 ff ff ff 0c 38 90 01 01 ff ff ff 0c 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}