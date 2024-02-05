
rule Trojan_BAT_Astaroth_psyZ_MTB{
	meta:
		description = "Trojan:BAT/Astaroth.psyZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {73 75 01 00 06 0a 06 03 7d 06 01 00 04 00 00 7e d1 00 00 04 06 fe 06 76 01 00 06 73 dc 01 00 0a 6f dd 01 00 0a 00 73 6d 01 00 0a 80 d1 00 00 04 00 de 05 26 00 00 de 00 06 7b 06 01 00 04 04 05 0e 04 28 3f 02 00 06 00 02 72 38 fb 08 70 6f f3 00 00 0a a5 6e 00 00 01 0b 07 2c 10 06 7b 06 01 00 04 04 05 0e 04 28 2f 01 00 06 00 } //00 00 
	condition:
		any of ($a_*)
 
}