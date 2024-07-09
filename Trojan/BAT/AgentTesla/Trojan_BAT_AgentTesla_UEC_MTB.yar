
rule Trojan_BAT_AgentTesla_UEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.UEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {38 05 00 00 00 38 00 00 00 00 11 00 2a 00 02 28 ?? ?? ?? 06 13 00 38 e5 ff ff ff } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {42 00 69 00 6e 00 61 00 72 00 79 00 46 00 69 00 6c 00 65 00 53 00 63 00 68 00 65 00 6d 00 61 00 47 00 55 00 49 00 } //1 BinaryFileSchemaGUI
		$a_01_4 = {44 00 69 00 63 00 74 00 69 00 6f 00 6e 00 61 00 72 00 79 00 45 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 6f 00 72 00 } //1 DictionaryEnumerator
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}