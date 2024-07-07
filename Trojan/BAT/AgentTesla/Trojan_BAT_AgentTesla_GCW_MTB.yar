
rule Trojan_BAT_AgentTesla_GCW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 2d 9d 6f 90 01 03 0a 0a 06 8e 69 8d 90 01 04 0b 16 13 06 2b 15 07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //10
		$a_80_1 = {55 46 55 45 59 48 49 } //UFUEYHI  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}