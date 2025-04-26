
rule Trojan_BAT_AgentTesla_RDAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 03 28 03 00 00 2b 28 04 00 00 2b 13 03 } //2
		$a_01_1 = {48 6a 78 63 73 65 75 67 61 6a 69 } //1 Hjxcseugaji
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}