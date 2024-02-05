
rule Trojan_Win32_Emotetcrypt_HI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d1 2b 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 03 d1 2b 15 90 01 04 03 15 90 01 04 03 15 90 01 04 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 0f af 15 90 00 } //01 00 
		$a_81_1 = {5f 76 61 5a 26 53 74 33 67 69 45 31 50 72 21 62 28 29 28 53 77 54 64 4b 36 49 37 61 23 4f 62 47 43 4a 6a 48 31 74 46 49 34 75 71 26 2a 62 56 62 25 39 4f 33 36 4c 4d 26 49 26 } //00 00 
	condition:
		any of ($a_*)
 
}