
rule Trojan_BAT_AsyncRat_NEBD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 26 17 da 0c 16 0d 2b 24 7e 0b 00 00 04 07 09 16 6f 3c 00 00 0a 25 26 13 04 12 04 28 3d 00 00 0a 25 26 6f 3e 00 00 0a 00 09 17 d6 0d 09 08 31 d8 } //00 00 
	condition:
		any of ($a_*)
 
}