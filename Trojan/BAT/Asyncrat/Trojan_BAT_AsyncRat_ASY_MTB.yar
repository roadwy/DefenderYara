
rule Trojan_BAT_AsyncRat_ASY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 26 28 90 01 03 06 25 26 02 20 60 01 00 00 28 90 01 03 06 02 8e 69 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASY_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 13 00 00 01 0a 06 72 41 00 00 70 6f 90 01 01 00 00 0a 00 72 49 00 00 70 0b 06 6f 90 01 01 00 00 0a 74 14 00 00 01 0c 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASY_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 2d 06 08 6f 90 01 03 0a 03 08 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 0d 07 09 28 90 01 03 0a 8c 3e 00 00 01 28 90 01 03 0a 0b 08 17 58 0c 08 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}