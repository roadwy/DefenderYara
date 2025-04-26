
rule Trojan_BAT_AgentTesla_JUB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 03 07 03 6f ?? ?? ?? 0a 5d 17 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 59 0c 06 08 28 ?? ?? ?? 0a 0d 12 03 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 02 16 fe 01 } //1
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}