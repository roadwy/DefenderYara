
rule Trojan_BAT_AsyncRat_AERB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AERB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 11 04 11 0a 11 04 91 11 0c 11 04 11 0c 8e 69 5d 91 61 d2 9c 00 11 04 17 58 13 04 11 04 11 0a 8e 69 fe 04 13 12 11 12 2d d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}