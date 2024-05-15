
rule Trojan_BAT_AsyncRat_SGE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.SGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e 0b 00 00 04 6f 1d 00 00 0a 6f 1e 00 00 0a 74 2e 00 00 01 28 19 00 00 0a 7e 07 00 00 04 6f 1f 00 00 0a 28 49 00 00 06 72 01 00 00 70 28 20 00 00 0a 7e 0a 00 00 04 28 1a 00 00 0a 6f 21 00 00 0a 0a dd 08 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}