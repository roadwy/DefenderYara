
rule Trojan_BAT_AgentTesla_GYA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 81 00 00 00 38 86 00 00 00 1a 2c 60 17 2c 5e 38 81 00 00 00 38 82 00 00 00 7d 04 00 00 04 00 38 7d 00 00 00 38 82 00 00 00 38 83 00 00 00 38 84 00 00 00 38 89 00 00 00 fe 06 0d 00 00 06 73 2e 00 00 0a 28 90 01 03 2b 25 2d 09 26 1e 2c b0 72 75 01 00 70 0c 07 08 6f 90 01 03 0a 0d 73 31 00 00 0a 13 04 09 11 04 6f 90 01 03 0a 00 11 04 6f 90 01 03 0a 13 05 11 05 13 06 1c 2c e7 18 2c 9f 2b 00 11 06 2a 73 0c 00 00 06 38 75 ff ff ff 0a 38 74 ff ff ff 06 38 79 ff ff ff 02 38 78 ff ff ff 28 90 01 03 0a 38 79 ff ff ff 0b 38 78 ff ff ff 07 38 77 ff ff ff 6f 90 01 03 0a 38 72 ff ff ff 06 38 71 ff ff ff 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}