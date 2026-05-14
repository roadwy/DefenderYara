
rule Trojan_BAT_AgentTesla_NCX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 03 16 03 8e 69 6f 18 00 00 0a 11 05 6f 19 00 00 0a 11 04 6f 1a 00 00 0a 13 06 11 06 8e 69 28 a9 00 00 06 0c 11 06 16 08 16 11 06 8e 69 28 1b 00 00 0a 08 13 07 dd 2b 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_NCX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 20 dc 05 00 00 73 2c 00 00 0a 0d 08 09 1f 20 ?? ?? 00 00 0a ?? ?? 00 00 0a 08 09 1f 10 ?? ?? 00 00 0a ?? ?? 00 00 0a 08 17 ?? ?? 00 00 0a 07 08 ?? ?? 00 00 0a 17 73 32 00 00 0a 13 04 11 04 02 16 02 8e 69 ?? ?? 00 00 0a 11 04 ?? ?? 00 00 0a de 0c } //2
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}