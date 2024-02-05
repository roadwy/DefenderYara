
rule Trojan_Win64_Bazarldr_ZV{
	meta:
		description = "Trojan:Win64/Bazarldr.ZV,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_01_1 = {41 b9 12 01 00 00 } //0a 00 
		$a_01_2 = {41 b8 1b 01 00 00 } //0a 00 
		$a_01_3 = {41 b9 92 04 00 00 } //0a 00 
		$a_01_4 = {41 b8 9b 04 00 00 } //0a 00 
		$a_01_5 = {00 00 00 00 01 00 00 80 00 00 00 80 00 00 00 01 00 01 } //00 00 
		$a_00_6 = {5d 04 00 00 dc a3 04 80 5c 32 00 00 dd a3 04 80 00 00 01 00 08 00 1c 00 54 72 6f 6a 61 6e 3a 57 69 6e 36 34 2f 42 61 7a 61 72 6c 64 72 2e 5a 56 21 73 } //6d 73 
	condition:
		any of ($a_*)
 
}