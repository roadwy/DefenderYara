
rule Trojan_BAT_AgentTesla_GT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 2c 14 09 72 ?? ?? ?? 70 07 08 1b 5b 18 58 93 28 ?? ?? ?? 0a 60 0d 20 ff 00 00 00 09 1f 0f 08 1b 5d 59 1e 59 1f 1f 5f 63 5f 0d 06 09 d2 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 26 00 08 1e 58 0c 08 02 6f ?? ?? ?? 0a 1b 5a fe 04 13 06 11 06 3a 67 ff ff ff } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {53 6e 61 6b 65 } //1 Snake
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}