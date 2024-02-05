
rule Trojan_BAT_AsyncRat_NEAJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0a 00 06 72 01 00 00 70 7d 03 00 00 04 06 28 0a 00 00 06 06 fe 06 0c 00 00 06 73 0b 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 7d 04 00 00 04 06 fe 06 0d 00 00 06 73 0e 00 00 0a 28 03 00 00 2b 6f 10 00 00 0a 0b 07 0c } //00 00 
	condition:
		any of ($a_*)
 
}