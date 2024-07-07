
rule Trojan_BAT_Dothetuk_AM_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 08 06 6f 90 01 01 00 00 0a 08 08 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0d 73 90 01 01 00 00 0a 13 04 11 04 09 17 73 90 01 01 00 00 0a 13 05 11 05 02 16 02 8e 69 6f 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a 0b de 90 00 } //4
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntivirusProduct
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}