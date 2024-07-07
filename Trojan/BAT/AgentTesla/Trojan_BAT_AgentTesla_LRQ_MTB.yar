
rule Trojan_BAT_AgentTesla_LRQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1f 11 06 07 08 28 90 01 03 06 13 07 11 07 28 90 01 03 0a 13 08 11 05 09 11 08 d2 9c 08 17 58 0c 08 17 fe 04 13 09 11 09 2d d7 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}