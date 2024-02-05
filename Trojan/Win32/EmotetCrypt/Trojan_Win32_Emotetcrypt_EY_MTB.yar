
rule Trojan_Win32_Emotetcrypt_EY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 30 8b 44 24 90 01 01 88 14 08 8b 54 24 90 01 01 8a 44 24 90 01 01 88 04 32 8b 54 24 90 01 01 0f b6 04 32 8b 54 24 90 01 01 0f b6 14 0a 03 c2 33 d2 f7 f5 03 54 24 90 01 01 8b 44 24 90 01 01 03 d3 8a 14 02 8b 44 24 90 01 01 30 14 38 90 00 } //01 00 
		$a_81_1 = {68 62 6a 5e 53 62 5a 4d 51 6f 5e 2b 38 6f 67 71 44 2a 6c 6c 4c 7a 47 33 55 39 76 51 2a 49 2a 31 57 52 66 6c 40 45 65 42 65 64 33 4b 57 30 25 56 4b 26 4c 70 75 49 72 3f 40 6b 54 73 30 25 2a 42 23 6d 6b 38 5f 64 40 55 2a 4c 37 4c 4d 7a 56 45 76 77 75 2a 75 47 36 72 6a 47 78 71 58 57 31 71 55 21 } //00 00 
	condition:
		any of ($a_*)
 
}