
rule Trojan_BAT_AsyncRat_CXJP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1c d2 13 37 11 1c 1e 63 d1 13 1c 11 1a 11 09 91 13 25 11 1a 11 09 11 25 11 2d 61 19 11 1f 58 61 11 37 61 d2 9c 11 25 13 1f 17 11 09 58 13 09 11 09 11 26 32 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}