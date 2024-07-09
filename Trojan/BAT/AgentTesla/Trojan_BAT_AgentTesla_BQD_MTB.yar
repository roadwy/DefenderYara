
rule Trojan_BAT_AgentTesla_BQD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {14 13 04 14 0c 16 0a 16 13 05 16 13 06 02 73 ?? ?? ?? 0a 16 73 ?? ?? ?? 0a 13 0a 11 0a 0c 08 13 07 20 00 10 00 00 8d ?? ?? ?? 01 13 08 73 ?? ?? ?? 0a 0b 08 11 08 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 0c 11 0c 0a 2b } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}