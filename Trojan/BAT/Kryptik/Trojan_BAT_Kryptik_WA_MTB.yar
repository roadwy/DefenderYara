
rule Trojan_BAT_Kryptik_WA_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.WA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 6e 17 6a d6 20 [0-04] 6a 5f b8 0c 09 11 05 08 84 95 d7 6e 20 [0-04] 6a 5f b8 0d 11 05 08 84 95 13 04 11 05 08 84 11 05 09 84 95 9e } //10
		$a_03_1 = {11 05 09 84 11 04 9e 11 06 11 08 03 11 08 91 11 05 11 05 08 84 95 11 05 09 84 95 d7 6e 20 [0-04] 6a 5f b7 95 61 86 9c 11 08 17 d6 13 08 11 08 11 07 31 9b } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}