
rule Trojan_BAT_AsyncRat_CXIO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 8e 69 33 02 16 0d 08 11 04 07 11 04 91 06 09 93 28 90 01 04 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 11 04 07 8e 69 32 d5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}