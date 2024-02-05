
rule Trojan_BAT_AgentTesla_CAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {61 2b ae 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 90 01 01 00 00 06 03 04 17 58 08 5d 91 28 90 01 01 00 00 06 59 06 58 06 5d d2 0d 11 04 20 f4 da 76 13 5a 20 39 ec 43 75 61 38 90 01 01 ff ff ff 11 04 20 2d e4 1d f9 5a 20 a9 cc 2c 0a 61 38 90 01 01 ff ff ff 03 8e 69 17 59 17 58 0c 11 04 20 b9 7e 2d 6b 5a 20 82 94 ad 74 61 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}