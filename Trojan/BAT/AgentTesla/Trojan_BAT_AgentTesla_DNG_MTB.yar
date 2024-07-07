
rule Trojan_BAT_AgentTesla_DNG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 90 01 03 06 03 08 17 58 03 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 90 00 } //1
		$a_01_1 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_2 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}