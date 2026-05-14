
rule Trojan_BAT_AsyncRat_ABA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 03 08 18 5a 18 6f ?? 00 00 0a 0d 06 08 09 1f 10 28 ?? 00 00 0a 9c 06 08 8f ?? 00 00 01 25 47 07 61 d2 52 00 08 17 58 0c 08 06 8e 69 fe 04 13 04 11 04 2d cb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AsyncRat_ABA_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 8d 7e 00 00 01 25 16 12 05 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 20 ?? ca e4 b6 38 ?? fe ff ff 11 19 20 ?? e1 57 47 5a 20 ?? f4 ba 70 61 38 ?? fe ff ff 08 6f ?? 00 00 0a 1f 1f 5a 13 17 11 19 20 ?? af a8 02 5a 20 ?? 10 d4 8f 61 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}