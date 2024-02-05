
rule Trojan_Win32_Emotetcrypt_GY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d7 8d 3c 09 bd 90 01 04 2b ef 0f af ee bf 90 01 04 2b f8 8d 44 7d 00 0f af 05 90 01 04 03 d0 a1 90 01 04 8d 34 46 8d 04 85 90 01 04 0f af c1 d1 e6 2b d6 03 d3 8a 0c 10 8b 44 24 90 01 01 8a 18 32 d9 8b 4c 24 90 01 01 88 18 90 00 } //01 00 
		$a_81_1 = {61 33 74 72 37 6d 78 36 42 4a 72 73 37 3c 66 62 54 25 59 28 64 75 4a 28 4d 76 6a 52 40 30 64 41 62 35 21 51 6d 36 37 29 36 43 4b 76 77 55 68 37 4f 55 72 30 55 5f 72 58 46 68 4f 77 54 29 24 6b 48 39 71 77 24 55 40 6b } //00 00 
	condition:
		any of ($a_*)
 
}