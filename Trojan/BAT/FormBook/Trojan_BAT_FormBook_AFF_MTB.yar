
rule Trojan_BAT_FormBook_AFF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 06 2b 17 00 08 07 11 06 6f 90 01 03 0a 6f 90 01 03 0a 26 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d db 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 56 00 65 00 4d 00 61 00 79 00 42 00 61 00 79 00 } //00 00  QuanLyBanVeMayBay
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 21 12 0a 28 90 01 03 0a 13 0b 2b 16 12 0a 28 90 01 03 0a 13 0b 2b 0b 12 0a 28 90 01 03 0a 13 0b 2b 00 07 11 0b 6f 90 01 03 0a 00 00 11 09 17 58 13 09 11 09 09 fe 04 13 0e 11 0e 2d 97 90 00 } //01 00 
		$a_01_1 = {54 00 65 00 63 00 68 00 6e 00 69 00 74 00 65 00 } //00 00  Technite
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 04 2b 23 00 06 11 04 18 6f 90 01 03 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 90 01 03 0a d2 9c 00 11 04 18 58 13 04 11 04 06 6f 90 01 03 0a fe 04 13 06 11 06 2d cd 90 00 } //01 00 
		$a_01_1 = {51 00 75 00 61 00 6e 00 4c 00 79 00 4e 00 68 00 61 00 6e 00 53 00 75 00 } //00 00  QuanLyNhanSu
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 28 00 07 09 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 05 08 11 05 8c 5b 00 00 01 6f 90 01 03 0a 26 09 18 58 0d 00 09 07 6f 90 01 03 0a fe 04 13 06 11 06 2d c9 90 00 } //01 00 
		$a_01_1 = {53 00 75 00 64 00 6f 00 6b 00 75 00 47 00 61 00 6d 00 65 00 } //00 00  SudokuGame
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AFF_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2e 00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f 90 01 03 0a 13 0a 07 12 0a 28 90 01 03 0a 6f 90 01 03 0a 00 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c4 90 00 } //01 00 
		$a_01_1 = {51 00 4c 00 5f 00 4b 00 41 00 52 00 41 00 4f 00 4b 00 45 00 } //00 00  QL_KARAOKE
	condition:
		any of ($a_*)
 
}