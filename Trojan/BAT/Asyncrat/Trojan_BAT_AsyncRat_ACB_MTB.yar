
rule Trojan_BAT_AsyncRat_ACB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 59 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 20 e8 03 00 00 58 13 04 11 04 09 2f 12 fe 13 7e ?? 00 00 04 2c 09 fe 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}