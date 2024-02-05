
rule Trojan_BAT_AsyncRat_NEG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {6f 0d 00 00 0a a4 0b 00 00 01 11 12 28 0e 00 00 0a 6f 0f 00 00 0a 11 08 11 09 11 0a 28 10 00 00 0a } //03 00 
		$a_01_1 = {67 00 48 00 43 00 6b 00 4b 00 55 00 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}