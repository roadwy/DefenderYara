
rule Trojan_BAT_Guildma_psyX_MTB{
	meta:
		description = "Trojan:BAT/Guildma.psyX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 f4 1c 00 00 1f 10 6a 28 95 00 00 06 0a 1f 41 6a 28 95 00 00 06 0b 28 94 00 00 06 06 16 fe 01 5f 07 17 5f 17 fe 01 5f 28 94 00 00 06 16 fe 01 06 16 fe 01 16 fe 01 5f 07 17 5f 17 fe 01 5f 60 0c 08 2c 14 7e 89 00 00 04 72 20 25 00 70 28 72 00 00 0a 80 89 00 00 04 00 28 94 00 00 06 16 fe 01 06 16 fe 01 5f 07 17 5f 17 fe 01 5f 28 94 00 00 06 06 16 fe 01 16 fe 01 5f 07 17 5f 17 fe 01 5f 60 0c 08 2c 14 7e 89 00 00 04 72 f4 25 00 70 28 72 00 00 0a 80 89 00 00 04 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}