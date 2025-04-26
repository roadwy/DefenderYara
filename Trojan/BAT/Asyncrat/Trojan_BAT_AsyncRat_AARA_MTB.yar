
rule Trojan_BAT_AsyncRat_AARA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 0d 2b 30 03 09 28 ?? 00 00 0a 04 09 04 6f ?? 00 00 0a 5d 17 d6 28 ?? 00 00 0a da 0c 07 08 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 09 17 d6 0d 09 11 04 13 05 11 05 31 c7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}