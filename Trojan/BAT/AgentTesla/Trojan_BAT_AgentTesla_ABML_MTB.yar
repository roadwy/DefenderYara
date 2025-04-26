
rule Trojan_BAT_AgentTesla_ABML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 34 16 2b 34 2b 39 2b 3e 2b 06 2b 07 2b 08 de 1a 09 2b f7 08 2b f6 6f ?? 00 00 0a 2b f1 16 2d 06 09 6f ?? 00 00 0a 1b 2c f4 dc 2b 1d 6f ?? 00 00 0a 13 04 de 42 } //3
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}