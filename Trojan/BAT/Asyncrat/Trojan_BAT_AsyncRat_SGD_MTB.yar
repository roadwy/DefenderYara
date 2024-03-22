
rule Trojan_BAT_AsyncRat_SGD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 28 0c 00 00 0a 7e 02 00 00 04 6f 12 00 00 0a 28 19 00 00 06 72 01 00 00 70 28 13 00 00 0a 7e 03 00 00 04 28 0d 00 00 0a 6f 14 00 00 0a 0b de 05 } //00 00 
	condition:
		any of ($a_*)
 
}