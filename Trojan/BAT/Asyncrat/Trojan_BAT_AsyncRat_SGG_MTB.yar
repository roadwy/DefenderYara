
rule Trojan_BAT_AsyncRat_SGG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 0d 00 00 04 7e 09 00 00 04 6f 4f 00 00 06 28 07 00 00 0a 73 09 00 00 0a 80 0b 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}