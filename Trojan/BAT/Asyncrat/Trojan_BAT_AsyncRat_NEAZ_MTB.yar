
rule Trojan_BAT_AsyncRat_NEAZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0a 00 06 18 6f 52 00 00 0a 00 06 18 6f 53 00 00 0a 00 06 6f 54 00 00 0a 0b 07 02 16 02 8e 69 6f 55 00 00 0a 0c 08 0d de 0b } //01 00 
		$a_01_1 = {63 61 6c 63 5f 70 72 6f 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {53 74 61 79 41 77 61 79 5f } //00 00 
	condition:
		any of ($a_*)
 
}