
rule Trojan_BAT_AsyncRat_NE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 06 58 0b 72 90 01 01 00 00 70 12 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {46 6c 61 70 70 79 5f 42 69 72 64 5f 57 69 6e 64 6f 77 73 5f 46 6f 72 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AsyncRat_NE_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {41 7a 64 6f 4b 52 41 63 4e 63 75 73 6c 6b 57 70 6a 74 42 42 } //04 00 
		$a_01_1 = {4a 77 4b 59 52 66 62 56 47 6a 72 4b 66 54 69 76 4e 72 46 71 } //03 00 
		$a_01_2 = {57 33 66 61 73 63 61 63 61 78 63 } //03 00 
		$a_01_3 = {63 72 79 70 74 65 64 2e 65 78 65 } //03 00 
		$a_01_4 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //02 00 
		$a_01_5 = {4c 6f 6d 69 6e 65 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}