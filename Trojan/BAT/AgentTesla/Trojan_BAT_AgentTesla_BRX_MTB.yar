
rule Trojan_BAT_AgentTesla_BRX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 16 8c ?? ?? ?? 01 a2 14 14 28 ?? ?? ?? 0a 07 17 da 17 d6 8d ?? ?? ?? 01 0c 11 07 14 [0-05] 28 ?? ?? ?? 06 19 8d ?? ?? ?? 01 25 16 08 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 07 8c ?? ?? ?? 01 a2 25 13 04 14 14 19 8d ?? ?? ?? 01 25 16 17 9c 25 18 17 9c 25 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}