
rule Trojan_BAT_AgentTesla_MAAF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 51 06 00 70 06 72 5d 06 00 70 6f 90 01 01 00 00 0a 72 67 06 00 70 72 6b 06 00 70 90 00 } //2
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 } //1 System.Activator
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}