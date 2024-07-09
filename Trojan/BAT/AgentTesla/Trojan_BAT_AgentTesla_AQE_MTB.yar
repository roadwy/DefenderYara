
rule Trojan_BAT_AgentTesla_AQE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 02 16 28 ?? ?? ?? 0a 0b 06 02 1a 02 8e 69 1a 59 6f ?? ?? ?? 0a 07 ?? ?? ?? ?? ?? 0c 06 16 6a 6f ?? ?? ?? 0a 06 16 ?? ?? ?? ?? ?? 08 16 08 8e 69 6f ?? ?? ?? 0a 26 08 2a } //10
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_2 = {54 6f 41 72 72 61 79 } //ToArray  1
		$a_80_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //CryptoStreamMode  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=10
 
}