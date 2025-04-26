
rule Trojan_BAT_AgentTesla_DOK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 6c 23 00 ba f4 ee 2a 81 f7 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 13 06 12 06 28 ?? ?? ?? 0a 13 05 07 11 05 28 ?? ?? ?? 0a 0b 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b8 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}