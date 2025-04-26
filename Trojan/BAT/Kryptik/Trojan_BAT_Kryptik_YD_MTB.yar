
rule Trojan_BAT_Kryptik_YD_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.YD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 6e 17 6a d6 20 [0-04] 6a 5f b8 0d 11 04 11 06 09 84 95 d7 6e 20 [0-04] 6a 5f b8 13 04 11 06 09 84 95 13 05 11 06 09 84 11 06 11 04 84 95 9e 11 06 11 04 84 } //10
		$a_03_1 = {11 05 9e 11 07 07 28 [0-04] 03 07 28 [0-04] 91 11 06 11 06 09 84 95 11 06 11 04 84 95 d7 6e 20 [0-04] 6a 5f b7 95 61 86 9c 07 11 08 12 01 28 [0-04] 13 0a 11 0a 2d 8a } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}