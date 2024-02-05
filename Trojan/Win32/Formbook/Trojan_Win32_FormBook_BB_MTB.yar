
rule Trojan_Win32_FormBook_BB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 37 04 5d 34 f6 fe c0 34 7e 2c 7d 88 04 37 46 3b f3 72 } //02 00 
		$a_01_1 = {6a 40 68 00 30 00 00 68 00 09 3d 00 33 f6 56 ff d7 85 c0 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_BB_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f 7e da 81 90 02 30 90 13 90 02 30 46 90 02 30 8b 17 90 02 20 0f 6e fe 90 02 25 90 18 90 02 25 0f 6e da 90 02 25 0f ef df 90 00 } //01 00 
		$a_02_1 = {0f 7e da 66 90 02 30 90 13 90 02 30 46 90 02 30 8b 17 90 02 20 0f 6e fe 90 02 25 90 18 90 02 25 0f 6e da 90 02 25 0f ef df 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_BB_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.BB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 ec 08 31 c9 89 45 e8 8b 45 e8 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 } //05 00 
		$a_01_1 = {83 ec 14 31 c9 39 c1 0f 85 05 00 00 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}