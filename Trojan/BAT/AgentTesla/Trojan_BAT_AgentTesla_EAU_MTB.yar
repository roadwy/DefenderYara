
rule Trojan_BAT_AgentTesla_EAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 19 11 05 5a 6f 90 01 01 00 00 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 07 19 11 05 5a 17 58 6f 90 01 01 00 00 0a 13 07 11 07 1f 39 fe 02 13 09 11 09 2c 0d 11 07 1f 41 59 1f 0a 58 d1 13 07 2b 08 11 07 1f 30 59 d1 13 07 09 11 05 1f 10 11 06 5a 11 07 58 d2 9c 00 11 05 17 58 13 05 11 05 08 fe 04 13 0a 11 0a 2d 84 90 00 } //3
		$a_01_1 = {4d 00 61 00 72 00 6c 00 69 00 65 00 63 00 65 00 5f 00 41 00 6e 00 64 00 72 00 61 00 64 00 61 00 } //2 Marliece_Andrada
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}