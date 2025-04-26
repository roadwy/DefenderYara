
rule Trojan_BAT_AgentTesla_OZN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_02_0 = {08 11 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 05 02 28 ?? ?? ?? 0a 13 04 28 ?? ?? ?? 0a 11 05 11 04 16 11 04 8e b7 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 0b dd } //10
		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  2
		$a_80_2 = {49 6e 76 6f 6b 65 } //Invoke  2
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}