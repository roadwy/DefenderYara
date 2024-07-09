
rule Trojan_BAT_AgentTesla_NLG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 1b 5b 93 28 94 00 00 0a 1f 0a 62 0d 08 1b 5b 17 58 07 8e 69 fe 04 13 04 11 04 2c 1b 09 20 ?? ?? ?? ?? 28 36 00 00 06 07 08 1b 5b 17 58 93 28 94 00 00 0a 1b 62 60 0d } //1
		$a_03_1 = {08 1b 5b 18 58 07 8e 69 fe 04 13 05 11 05 2c 19 09 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 07 08 1b 5b 18 58 93 28 94 00 00 0a 60 0d } //1
		$a_01_2 = {09 1f 0f 08 1b 5d 59 1e 59 1f 1f 5f 63 5f 0d 06 09 d2 6f 65 00 00 0a 08 1e 58 0c 08 02 6f 95 00 00 0a 1b 5a fe 04 13 06 11 06 3a 60 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}