
rule Trojan_BAT_AsyncRat_CCEF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CCEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e d5 35 00 04 06 7e d4 35 00 04 02 07 6f 90 01 01 00 00 0a 7e 86 35 00 04 07 7e 86 35 00 04 8e 69 5d 91 61 28 90 01 01 33 00 06 28 90 01 01 33 00 06 26 07 17 58 0b 07 02 6f 90 01 01 00 00 0a 32 c6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}