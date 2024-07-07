
rule Trojan_BAT_DCRat_LA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e b5 08 00 04 0e 06 17 59 95 58 0e 05 28 90 01 01 0d 00 06 58 54 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_DCRat_LA_MTB_2{
	meta:
		description = "Trojan:BAT/DCRat.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 95 61 54 11 12 11 15 1f 0f 5f 11 12 11 15 1f 0f 5f 95 11 08 25 1a 58 13 08 4b 61 90 01 05 58 9e 11 15 17 58 13 15 11 23 17 58 90 00 } //5
		$a_01_1 = {11 0b 16 95 11 1e 25 1a 58 13 1e 4b 61 11 0c 16 95 58 11 0d 16 95 11 0e 16 95 5a 58 13 21 11 0b } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}