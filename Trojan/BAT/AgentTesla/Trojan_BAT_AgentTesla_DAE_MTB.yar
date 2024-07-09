
rule Trojan_BAT_AgentTesla_DAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 03 8e 69 17 59 17 58 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? 00 00 0a 03 04 17 58 08 5d 91 28 ?? 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_DAE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 04 06 11 04 28 ?? ?? ?? 06 07 da 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0a 00 09 17 d6 0d 09 08 28 ?? ?? ?? 06 fe 04 13 05 11 05 2d c8 } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}