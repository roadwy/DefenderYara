
rule Trojan_Win32_TrickbotCrypt_SE_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 c0 83 c9 ff 8b 7d 90 01 01 f2 ae f7 d1 49 89 d8 31 d2 f7 f1 8a 04 16 8b 55 90 01 01 32 04 1a 8b 55 90 01 01 88 04 1a ff 05 90 01 04 8b 1d 90 01 04 3b 5d 90 01 01 75 90 01 01 5b 5e 5f 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickbotCrypt_SE_MTB_2{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 8b 45 90 01 01 8a 04 38 02 45 0f 8a 0c 3a 02 4d 0f 88 04 3a 8b 45 90 01 01 88 0c 38 8b c2 0f b6 04 38 0f b6 c9 03 c1 89 55 90 01 01 33 d2 8b ce f7 f1 8b 4d 90 01 01 03 55 90 01 01 8a 04 3a 02 45 0f 32 04 19 88 03 43 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_03_1 = {ff d6 59 0d 00 10 00 00 50 ff 74 24 90 01 01 6a 00 ff d7 8b f0 85 f6 74 90 01 01 ff 74 24 90 01 01 56 6a 90 01 01 68 90 01 04 ff 74 24 90 01 01 53 ff 54 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}