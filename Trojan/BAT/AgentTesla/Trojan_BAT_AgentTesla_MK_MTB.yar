
rule Trojan_BAT_AgentTesla_MK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 3c 00 00 06 72 57 90 01 03 72 5b 90 01 03 6f 74 90 01 03 72 63 90 01 03 72 67 90 01 03 6f 74 90 01 03 72 6b 05 00 70 72 6f 05 00 70 6f 74 90 01 03 17 8d 61 00 00 01 25 16 1f 2d 9d 6f 75 90 01 03 0a 06 8e 69 8d 62 00 00 01 0b 16 13 06 2b 15 07 11 06 06 11 06 9a 1f 10 28 76 90 01 03 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}