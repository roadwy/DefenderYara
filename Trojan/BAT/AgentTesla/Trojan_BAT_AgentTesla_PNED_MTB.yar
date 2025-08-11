
rule Trojan_BAT_AgentTesla_PNED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PNED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 20 e8 03 00 00 5d 16 fe 01 13 0c 11 0c 2c 27 00 28 ?? 00 00 0a 08 28 ?? 00 00 0a 13 0f 12 0f 28 ?? 00 00 0a 69 13 0d 09 6c 17 11 0d 28 ?? 00 00 0a 6c 5b 13 0e 00 00 07 06 59 } //4
		$a_01_1 = {00 07 11 05 07 11 05 94 02 5a 1f 64 5d 9e 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d de } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}