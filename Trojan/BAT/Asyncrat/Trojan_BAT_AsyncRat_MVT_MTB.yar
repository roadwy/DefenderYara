
rule Trojan_BAT_AsyncRat_MVT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 02 11 05 02 11 05 91 20 a9 00 00 00 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 d8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}