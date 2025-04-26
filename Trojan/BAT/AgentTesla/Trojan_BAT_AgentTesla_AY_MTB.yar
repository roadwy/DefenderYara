
rule Trojan_BAT_AgentTesla_AY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 91 03 17 91 61 d2 9c 06 07 06 07 91 1f 18 61 d2 9c 06 07 03 08 91 03 16 91 03 17 91 61 d2 61 d2 9c 07 17 58 0b 08 17 58 0c 08 03 8e 69 32 cd } //2
		$a_01_1 = {72 00 32 00 72 00 65 00 73 00 75 00 72 00 72 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 72 00 75 00 } //2 r2resurrection.ru
		$a_01_2 = {58 6f 72 44 65 63 6f 64 65 } //1 XorDecode
		$a_01_3 = {58 6f 72 45 6e 63 6f 64 65 } //1 XorEncode
		$a_01_4 = {42 61 73 65 36 34 44 65 63 6f 64 65 45 78 } //1 Base64DecodeEx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}