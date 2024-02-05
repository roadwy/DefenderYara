
rule Trojan_BAT_AsyncRat_AG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 07 11 04 8f 15 00 00 01 72 77 00 00 70 28 90 01 03 0a a2 11 04 17 58 13 04 11 04 6a 08 6e 32 dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}