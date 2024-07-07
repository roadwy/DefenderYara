
rule Trojan_BAT_NjRat_NEV_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 38 00 00 0a 14 18 8d 17 00 00 01 25 16 11 04 72 90 01 01 01 00 70 28 33 00 00 0a a2 25 17 09 28 35 00 00 0a a2 6f 39 00 00 0a 26 de 0f 90 00 } //5
		$a_01_1 = {6b 00 72 00 6f 00 77 00 65 00 6d 00 61 00 72 00 46 00 5c 00 54 00 45 00 4e 00 2e 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 3a 00 43 00 } //2 krowemarF\TEN.tfosorciM\swodniW\:C
		$a_01_2 = {39 00 31 00 33 00 30 00 33 00 2e 00 30 00 2e 00 34 00 76 00 } //1 91303.0.4v
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}