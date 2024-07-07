
rule Trojan_BAT_AgentTesla_NKP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 07 08 1b 5b 93 28 69 00 00 0a 1f 0a 62 0d 08 1b 5b 17 58 07 8e 69 fe 04 13 04 11 04 2c 16 } //1
		$a_01_1 = {70 07 08 1b 5b 17 58 93 28 69 00 00 0a 1b 62 60 0d 08 1b 5b 18 58 07 8e 69 fe 04 13 05 11 05 2c 14 } //1
		$a_01_2 = {07 08 1b 5b 18 58 93 28 69 00 00 0a 60 0d 20 ff 00 00 00 09 1f 0f 08 1b 5d 59 1e 59 1f 1f 5f 63 5f 0d 06 09 d2 6f 6a 00 00 0a 00 00 08 1e 58 0c 08 02 6f 53 00 00 0a 1b 5a fe 04 13 06 11 06 3a 6c ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}