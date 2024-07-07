
rule Trojan_BAT_Kryptik_TU_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 90 02 04 03 6f 90 02 04 6f 90 02 04 0c 06 08 6f 90 02 05 06 18 6f 90 02 05 06 6f 90 02 04 02 16 02 8e 69 6f 90 02 04 0d 09 13 04 2b 00 11 04 2a 90 00 } //10
		$a_00_1 = {69 00 a4 06 2e 06 27 06 54 00 35 06 49 06 4a 04 35 04 45 06 09 54 55 00 0c 20 34 06 46 06 09 54 17 5f } //10
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}