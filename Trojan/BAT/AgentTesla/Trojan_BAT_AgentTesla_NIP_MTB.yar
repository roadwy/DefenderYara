
rule Trojan_BAT_AgentTesla_NIP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 22 11 04 06 07 6f 90 01 03 0a 13 05 11 05 28 90 01 03 0a 13 06 09 06 11 06 d2 6f 90 01 03 0a 07 17 58 0b 07 17 fe 04 13 07 11 07 2d d4 08 17 58 0c 06 90 00 } //1
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}