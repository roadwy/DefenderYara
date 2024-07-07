
rule Trojan_BAT_AgentTesla_CAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 03 04 03 8e 69 5d 91 07 04 05 5d 91 61 28 90 01 01 01 00 0a 6e 03 04 17 58 03 8e 69 5d 91 28 90 01 01 01 00 0a 6a 59 06 6a 58 06 6a 5d d2 0c 2b 00 08 2a 90 00 } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}