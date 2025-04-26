
rule Trojan_BAT_AsyncRat_AXKA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AXKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 19 58 19 59 91 61 03 08 20 10 02 00 00 58 20 0f 02 00 00 59 18 59 18 58 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}