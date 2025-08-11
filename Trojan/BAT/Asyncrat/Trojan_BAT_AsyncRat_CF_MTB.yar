
rule Trojan_BAT_AsyncRat_CF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 8e 69 5d 91 08 61 11 04 1f 1f 5a 61 d2 13 06 09 11 04 11 05 11 06 61 d2 9c 11 04 17 58 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}