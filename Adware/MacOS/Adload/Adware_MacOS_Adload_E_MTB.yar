
rule Adware_MacOS_Adload_E_MTB{
	meta:
		description = "Adware:MacOS/Adload.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {d1 28 05 b2 11 19 c5 28 05 f1 11 08 ef 2c 05 89 13 1d a6 31 03 a6 13 40 da 32 03 e6 13 0f 8f 2e 03 fe 13 0c f7 2d 03 90 14 0f e2 2d 03 9f 14 26 ca 2d 03 c8 14 0f b6 2d 03 a9 15 16 c3 31 03 bf 15 16 f0 30 03 e5 15 13 ab 31 03 89 16 13 93 2f 03 a7 16 16 e7 2b 03 92 17 0f af 32 03 a1 17 31 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}