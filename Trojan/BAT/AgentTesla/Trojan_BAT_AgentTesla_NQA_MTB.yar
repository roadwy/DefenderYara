
rule Trojan_BAT_AgentTesla_NQA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 00 07 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 06 08 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 02 0d 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 de 16 } //1
		$a_01_1 = {54 6f 42 75 66 66 65 72 } //1 ToBuffer
		$a_01_2 = {6e 65 77 4e 6f 64 65 } //1 newNode
		$a_01_3 = {69 73 45 6d 70 74 79 } //1 isEmpty
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}