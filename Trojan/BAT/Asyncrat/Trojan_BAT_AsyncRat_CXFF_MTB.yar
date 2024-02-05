
rule Trojan_BAT_AsyncRat_CXFF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.CXFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 08 6c 07 6c 28 90 01 0d 5b 90 01 09 58 0d 09 90 01 09 34 0c 90 01 09 0d 2b 24 09 90 01 09 36 0c 90 01 09 0d 2b 0c 09 90 01 09 5a 0d 06 08 07 1f 1e 09 69 09 69 09 69 28 90 01 04 6f 90 01 04 08 17 58 0c 08 03 32 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}