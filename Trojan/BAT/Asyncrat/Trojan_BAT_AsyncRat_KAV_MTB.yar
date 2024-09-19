
rule Trojan_BAT_AsyncRat_KAV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 93 13 06 11 06 09 d6 6a 13 07 07 11 07 20 80 00 00 00 6a da b7 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 11 05 17 d6 13 05 11 05 11 04 8e 69 fe 04 13 08 11 08 2d c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}