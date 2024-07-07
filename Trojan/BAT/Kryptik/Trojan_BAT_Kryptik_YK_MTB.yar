
rule Trojan_BAT_Kryptik_YK_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.YK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 5f 88 13 04 11 05 08 11 04 84 95 d7 6e 20 90 02 04 6a 5f 88 13 05 08 11 04 84 95 13 06 08 11 04 84 08 11 05 84 95 9e 08 11 05 84 11 06 90 00 } //10
		$a_03_1 = {9e 09 11 08 03 11 08 91 08 08 11 04 84 95 08 11 05 84 95 d7 6e 20 90 02 04 6a 5f 84 95 61 86 9c 11 08 17 d6 13 08 00 11 08 11 07 fe 02 13 0c 11 0c 2c 04 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}