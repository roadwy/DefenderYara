
rule Trojan_Win64_Miancha_CAF_MTB{
	meta:
		description = "Trojan:Win64/Miancha.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 89 07 01 00 ff 90 01 05 48 8b c8 48 8d 15 89 07 01 00 ff 90 01 05 41 b9 0a 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 84 24 c0 00 00 00 33 c9 48 8d 90 01 05 ff 90 01 01 33 d2 48 8d 8c 24 c0 00 00 00 ff 90 01 05 48 8b 8c 24 d0 01 00 00 90 00 } //01 00 
		$a_01_1 = {63 6d 64 73 68 65 6c 6c } //01 00 
		$a_01_2 = {63 6d 64 73 68 65 6c 6c 5f 64 65 69 6e 69 74 } //01 00 
		$a_01_3 = {63 6d 64 73 68 65 6c 6c 5f 69 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}