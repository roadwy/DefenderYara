
rule Trojan_BAT_AgentTesla_CAR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 03 8e 69 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? 00 00 0a 03 04 17 58 08 5d 91 28 ?? 00 00 0a 59 06 58 06 5d d2 0d 09 2a } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}