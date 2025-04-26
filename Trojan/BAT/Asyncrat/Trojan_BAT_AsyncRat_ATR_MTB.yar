
rule Trojan_BAT_AsyncRat_ATR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e b7 17 da 13 07 13 06 2b 21 09 11 06 91 11 04 11 06 11 04 8e b7 5d 91 61 13 05 08 11 05 6f ?? ?? ?? 0a 00 00 11 06 17 d6 13 06 11 06 11 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}