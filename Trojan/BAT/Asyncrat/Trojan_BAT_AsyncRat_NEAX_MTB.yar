
rule Trojan_BAT_AsyncRat_NEAX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 2c 0b 02 6f 1f 00 00 0a 17 5f 17 33 06 73 20 00 00 0a 7a 73 21 00 00 0a 0a 16 0b 2b 1c 02 07 18 6f 22 00 00 0a 0c 06 08 1f 10 28 23 00 00 0a 6f 24 00 00 0a 26 07 18 58 0b 07 02 6f 1f 00 00 0a 32 db } //05 00 
		$a_01_1 = {74 00 75 00 74 00 6f 00 72 00 69 00 61 00 6c 00 2e 00 67 00 79 00 61 00 } //00 00  tutorial.gya
	condition:
		any of ($a_*)
 
}