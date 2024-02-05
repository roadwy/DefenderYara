
rule Trojan_BAT_AsyncRat_NEO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 08 6f 16 00 00 0a 0d 00 09 28 17 00 00 0a 03 28 18 00 00 0a 1f 1e 5d 5b 28 19 00 00 0a 13 05 12 05 28 1a 00 00 0a 13 04 06 11 04 6f 1b 00 00 0a 26 00 08 17 58 0c } //00 00 
	condition:
		any of ($a_*)
 
}