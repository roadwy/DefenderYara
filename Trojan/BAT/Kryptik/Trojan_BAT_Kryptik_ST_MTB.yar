
rule Trojan_BAT_Kryptik_ST_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ST!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 07 1f 61 32 0a 07 1f 7a fe 02 16 fe 01 2b 01 16 0c 08 2c 1e 07 1f 6d fe 02 16 fe 01 0d 09 2c 08 07 1f 0d d6 0b 00 2b 07 00 07 1f 0d da 0b 00 00 2b 34 07 1f 41 32 0a } //10
		$a_01_1 = {07 1f 5a fe 02 16 fe 01 2b 01 16 13 04 11 04 2c 1e 07 1f 4d fe 02 16 fe 01 13 05 11 05 2c 08 07 1f 0d d6 0b 00 2b 07 00 07 1f 0d da 0b 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}