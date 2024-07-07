
rule Trojan_BAT_AgentTesla_LVA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff 90 01 06 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 06 2a 90 00 } //1
		$a_03_1 = {0a 13 04 11 04 28 90 01 03 06 28 90 01 03 0a 13 05 07 11 05 28 90 01 03 0a 0b 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 06 11 06 2d cd 90 00 } //1
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {4c 61 74 65 47 65 74 } //1 LateGet
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}