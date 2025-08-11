
rule Trojan_BAT_AsyncRat_ZZT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ZZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 08 8e 69 8d ?? 00 00 01 13 04 16 13 05 2b 12 11 04 11 05 08 11 05 91 09 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 0e 11 0e 2d e1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}