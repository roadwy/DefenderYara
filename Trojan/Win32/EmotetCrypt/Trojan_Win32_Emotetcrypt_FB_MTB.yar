
rule Trojan_Win32_Emotetcrypt_FB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ca 03 0d 90 01 04 8b 45 d4 03 c8 8b 55 d8 2b ca 03 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 8b 45 dc 2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d 90 01 04 2b 0d 90 01 04 8b 55 0c 8b 45 e8 88 04 0a 90 00 } //01 00 
		$a_81_1 = {62 49 53 21 62 21 55 33 34 31 4d 78 56 29 51 75 36 35 78 5e 45 51 71 26 57 34 35 30 35 4c 29 6d 65 38 61 72 6a 6e 35 65 23 4c 30 62 79 5e 56 21 21 58 3f 32 4a 79 71 6d 50 67 40 } //00 00 
	condition:
		any of ($a_*)
 
}