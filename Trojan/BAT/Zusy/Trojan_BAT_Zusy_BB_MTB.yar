
rule Trojan_BAT_Zusy_BB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 09 1e 38 ?? ff ff ff 11 09 72 ?? 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 09 1f 09 38 ?? ff ff ff 28 ?? 00 00 0a 11 07 28 ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 14 18 8d } //4
		$a_03_1 = {13 1a 11 1a 28 ?? 00 00 0a 13 1a 00 72 ?? 06 00 70 28 ?? 00 00 0a 13 1b 11 1b 72 ?? 06 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 1b 28 ?? 00 00 0a 11 17 28 ?? 00 00 0a 6f ?? 00 00 0a 72 } //4
		$a_01_2 = {6b 00 72 00 6f 00 77 00 65 00 6d 00 61 00 72 00 46 00 5c 00 54 00 45 00 4e 00 2e 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 3a 00 43 00 } //1 krowemarF\TEN.tfosorciM\swodniW\:C
		$a_01_3 = {39 00 31 00 33 00 30 00 33 00 2e 00 30 00 2e 00 34 00 76 00 } //1 91303.0.4v
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}