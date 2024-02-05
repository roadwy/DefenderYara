
rule Trojan_Win32_Emotetcrypt_FI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 c4 03 f8 8b 4d c8 03 f9 8b 55 cc 03 fa 8b 45 d0 03 f8 2b 3d 90 01 04 8b 4d d4 03 f9 8b 55 d8 03 fa 8b 45 dc 03 f8 8b 4d e0 03 f9 8b 55 e4 03 55 0c 8b 45 e8 88 04 3a 90 00 } //01 00 
		$a_81_1 = {50 41 3f 4b 29 38 41 73 4a 4f 2b 24 72 57 34 49 50 6f 69 71 35 4a 79 66 38 71 6a 21 4f 70 69 70 35 5e 6e 4f 3e 6b 68 36 63 78 75 44 37 74 71 35 43 32 35 72 32 34 29 33 5f 48 78 31 76 2b 62 6d 4f 31 38 67 4e 5f 79 66 45 3e 44 21 59 72 6b 36 66 42 28 36 46 35 68 6c 4b 72 79 4f 78 } //00 00 
	condition:
		any of ($a_*)
 
}