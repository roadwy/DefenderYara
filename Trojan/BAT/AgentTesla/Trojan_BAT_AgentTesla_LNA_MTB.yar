
rule Trojan_BAT_AgentTesla_LNA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 31 00 09 11 04 11 05 6f ?? ?? ?? 0a 13 06 09 11 04 11 05 6f ?? ?? ?? 0a 13 07 17 13 08 00 08 07 02 11 07 28 ?? ?? ?? 06 d2 9c 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 09 11 09 2d c4 } //1
		$a_01_1 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_LNA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d de 15 } //1
		$a_01_1 = {00 45 78 61 6d 70 6c 65 00 67 65 74 5f 4e 61 6d 65 00 } //1 䔀慸灭敬最瑥也浡e
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_3 = {54 6f 42 79 74 65 41 72 72 61 79 } //1 ToByteArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}