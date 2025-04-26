
rule Trojan_BAT_AgentTesla_CTY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 07 08 20 e8 03 00 00 73 ?? ?? ?? 0a 0d 06 09 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 09 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 02 06 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 } //1
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00 43 6c 61 73 73 4c 69 62 72 61 72 79 } //1
		$a_01_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 } //1 GetManifestResource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}