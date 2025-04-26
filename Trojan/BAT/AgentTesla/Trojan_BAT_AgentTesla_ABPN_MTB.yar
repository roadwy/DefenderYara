
rule Trojan_BAT_AgentTesla_ABPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 07 08 6f ?? ?? ?? 0a 16 73 ?? ?? ?? 0a 13 06 73 ?? ?? ?? 0a 13 07 20 ?? ?? ?? 00 8d ?? ?? ?? 01 13 08 16 13 09 38 ?? ?? ?? 00 11 07 11 08 16 11 09 6f ?? ?? ?? 0a 11 06 11 08 16 11 08 8e 69 6f ?? ?? ?? 0a 25 13 09 16 30 e0 11 07 6f ?? ?? ?? 0a 0d dd ?? ?? ?? 00 11 07 39 ?? ?? ?? 00 11 07 6f ?? ?? ?? 0a dc } //4
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}