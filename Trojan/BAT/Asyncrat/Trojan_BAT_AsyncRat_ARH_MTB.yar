
rule Trojan_BAT_AsyncRat_ARH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 43 2b 48 2b 4d 2b 4e 2b 53 28 ?? 00 00 0a 0b 07 28 ?? 00 00 06 28 ?? 00 00 0a 18 2c 01 00 16 2d e4 07 0c 1c 2c f8 de 40 28 ?? 00 00 0a 2b bb 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}