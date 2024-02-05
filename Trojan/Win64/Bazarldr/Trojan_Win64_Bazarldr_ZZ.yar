
rule Trojan_Win64_Bazarldr_ZZ{
	meta:
		description = "Trojan:Win64/Bazarldr.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 83 ec 78 83 60 08 00 48 8b e9 b9 4c 77 26 07 44 8b fa 33 db e8 a4 04 00 00 b9 49 f7 02 78 4c 8b e8 e8 97 04 00 00 b9 58 a4 53 e5 } //01 00 
		$a_01_1 = {48 89 44 24 20 e8 88 04 00 00 b9 10 e1 8a c3 48 8b f0 e8 7b 04 00 00 b9 af b1 5c 94 } //01 00 
		$a_01_2 = {48 89 44 24 30 e8 6c 04 00 00 b9 33 00 9e 95 48 89 44 24 28 4c 8b e0 e8 5a 04 00 00 48 63 7d 3c } //00 00 
	condition:
		any of ($a_*)
 
}