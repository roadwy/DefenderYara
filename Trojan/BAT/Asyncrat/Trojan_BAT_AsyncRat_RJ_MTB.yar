
rule Trojan_BAT_AsyncRat_RJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 0e 11 06 17 58 13 06 11 06 11 05 8e 69 32 d1 06 16 8c 90 01 04 6f 90 01 03 0a 26 06 6f 90 01 03 0a 13 07 16 13 08 2b 34 11 07 11 08 9a 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}