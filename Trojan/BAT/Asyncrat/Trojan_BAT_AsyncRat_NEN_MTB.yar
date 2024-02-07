
rule Trojan_BAT_AsyncRat_NEN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {0a 28 0b 00 00 0a 06 28 0c 00 00 0a 6f 0d 00 00 0a 6f 0e 00 00 0a 72 01 00 00 70 14 6f 0f 00 00 0a 26 2a } //04 00 
		$a_01_1 = {56 00 51 00 6f 00 62 00 63 00 52 00 58 00 49 00 68 00 36 00 52 00 39 00 55 00 48 00 4b 00 48 00 52 00 78 00 } //00 00  VQobcRXIh6R9UHKHRx
	condition:
		any of ($a_*)
 
}