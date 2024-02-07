
rule Trojan_Win32_MokesCrypt_PA_MTB{
	meta:
		description = "Trojan:Win32/MokesCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c1 8b 0d 90 01 04 88 81 90 01 04 8b 15 90 01 04 0f b6 82 90 01 04 89 45 e0 a1 90 01 04 0f b6 88 90 01 04 33 4d e0 8b 15 90 01 04 88 8a 90 01 04 a1 90 01 04 0f b6 88 90 01 04 8b 15 90 01 04 0f b6 82 90 01 04 33 c1 8b 0d 90 01 04 88 81 90 01 04 e9 90 00 } //01 00 
		$a_03_1 = {03 c2 25 ff 00 00 80 79 90 01 01 48 0d 00 ff ff ff 40 0f b6 80 90 01 04 33 c8 8b 15 90 01 04 03 55 90 01 01 88 0a e9 21 90 00 } //01 00 
		$a_03_2 = {5c 74 65 73 74 34 5c 65 39 31 5c 90 02 10 5c 65 39 31 2e 70 64 62 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}