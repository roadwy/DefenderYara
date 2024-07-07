
rule Trojan_BAT_AgentTesla_BIN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {16 0b 04 17 da 0c 16 0a 2b 90 02 02 07 03 06 94 d6 0b 06 17 d6 0a 06 08 31 90 02 02 07 6c 04 6c 5b 02 02 7b 90 01 03 04 6f 90 01 03 0a 1f 0a 9a 7d 90 01 03 04 2a 90 00 } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}