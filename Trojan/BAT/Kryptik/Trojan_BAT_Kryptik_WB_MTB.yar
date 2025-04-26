
rule Trojan_BAT_Kryptik_WB_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.WB!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {1f 7a fe 02 16 fe 01 2b 01 16 13 61 11 61 2c 1f 00 06 1f 6d fe 02 13 62 11 62 2c 09 00 06 1f 0d 59 0a 00 2b 07 00 06 1f 0d 58 0a } //10
		$a_01_1 = {2b 33 06 1f 41 32 0a 06 1f 5a fe 02 16 fe 01 2b 01 16 13 63 11 63 2c 1d 00 06 1f 4d fe 02 13 64 11 64 2c 09 00 06 1f 0d 59 0a 00 2b 07 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}