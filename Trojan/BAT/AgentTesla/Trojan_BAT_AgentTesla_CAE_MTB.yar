
rule Trojan_BAT_AgentTesla_CAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 90 01 01 00 00 0a 05 03 17 58 05 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0a 2b 00 06 2a 90 00 } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}