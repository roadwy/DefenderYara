
rule Trojan_BAT_AgentTesla_LAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 11 04 28 ?? ?? ?? 0a 23 ?? ?? ?? ?? ?? ?? ?? 40 59 28 ?? ?? ?? 0a b7 13 05 07 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 8e 69 fe 04 13 06 11 06 2d } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}