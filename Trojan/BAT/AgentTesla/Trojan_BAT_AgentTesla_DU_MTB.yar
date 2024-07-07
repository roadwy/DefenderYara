
rule Trojan_BAT_AgentTesla_DU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 14 17 8d 90 01 03 1b 25 16 02 a2 90 09 50 00 16 8d 90 01 03 01 0a 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 73 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 0a 06 28 90 01 03 0a 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 06 28 90 01 03 0a 14 6f 90 01 03 0a 74 90 00 } //1
		$a_01_1 = {26 de 03 26 de 00 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}