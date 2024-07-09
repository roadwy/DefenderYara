
rule Trojan_BAT_AgentTesla_ASAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 16 2b 1c 12 12 28 ?? 01 00 0a 0d 2b 12 12 12 28 ?? 01 00 0a 0d 2b 08 12 12 28 ?? 01 00 0a 0d 11 07 09 6f ?? 00 00 0a 08 17 58 0c 08 11 08 fe 04 13 0e 11 0e 3a } //3
		$a_03_1 = {11 04 08 07 6f ?? 01 00 0a 13 12 16 0d 11 0a 06 9a 13 0d 11 0d 13 05 11 05 20 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}