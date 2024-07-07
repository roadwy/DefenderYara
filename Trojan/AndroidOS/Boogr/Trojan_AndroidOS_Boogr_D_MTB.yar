
rule Trojan_AndroidOS_Boogr_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Boogr.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 16 00 13 00 48 00 23 01 90 01 02 26 01 90 01 02 00 00 23 52 90 01 02 12 00 34 50 08 00 22 00 90 01 02 70 20 90 01 02 20 00 11 00 dc 03 00 48 49 04 06 00 44 03 01 03 b7 43 8e 33 50 03 02 00 d8 00 00 01 28 ec 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}