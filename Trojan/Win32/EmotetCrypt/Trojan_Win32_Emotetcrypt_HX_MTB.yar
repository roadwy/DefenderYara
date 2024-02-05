
rule Trojan_Win32_Emotetcrypt_HX_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c1 03 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b c1 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 2b 05 90 01 04 2b 05 90 01 04 8b 4d 0c 88 14 01 90 00 } //01 00 
		$a_81_1 = {5f 38 58 6e 48 69 44 7a 4d 46 54 77 4f 24 44 3c 52 65 67 2b 37 4a 77 72 69 6d 36 68 40 49 35 21 52 6b 73 23 73 69 4a 78 44 53 4c 35 6b 59 79 32 31 5a 6c 71 53 65 30 55 41 38 52 6d 51 29 41 2a 6e 7a 30 30 6a 4f 4a 4f 31 32 24 68 3c 44 58 41 35 63 35 74 7a 70 33 29 53 } //00 00 
	condition:
		any of ($a_*)
 
}