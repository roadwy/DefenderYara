
rule Trojan_BAT_AgentTesla_EQU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 11 05 17 da 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 08 11 05 08 6f 90 01 03 0a 5d 6f 90 01 03 0a da 90 09 07 00 07 17 8d 90 01 03 01 90 00 } //1
		$a_01_1 = {0d 59 8e 7f 3d 4e 8e 7f 0d 59 8e 7f 0d 59 36 52 0d 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}