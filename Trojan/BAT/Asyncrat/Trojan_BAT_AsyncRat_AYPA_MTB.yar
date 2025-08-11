
rule Trojan_BAT_AsyncRat_AYPA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AYPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 1c 58 1c 59 91 61 06 09 20 11 02 00 00 58 20 10 02 00 00 59 06 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1c 58 1c 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 09 17 58 0d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}