
rule Trojan_Win32_TrickbotCrypt_NO_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 8b 00 8b ea 8b 54 24 90 01 01 8a 14 10 32 14 29 8b 6c 24 90 01 01 88 14 28 a1 90 01 04 40 3b c3 a3 90 01 04 72 90 00 } //1
		$a_03_1 = {33 d2 8a 14 90 01 01 8b c3 25 ff 00 00 00 03 ea 03 c5 33 d2 f7 35 90 01 04 46 47 8b ea 8a 04 29 88 1c 29 88 47 90 01 01 a1 90 01 04 3b f0 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_TrickbotCrypt_NO_MTB_2{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 89 4d 90 01 01 c7 45 f4 00 00 00 00 eb 09 8b 55 90 01 01 83 c2 01 89 55 90 01 01 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 8a 02 88 01 eb 90 01 01 8b e5 5d c3 90 00 } //1
		$a_03_1 = {0f b7 4a 14 8d 54 08 90 01 01 89 55 90 01 01 c7 45 90 01 01 00 00 00 00 eb 90 01 01 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 83 c1 28 89 4d 90 01 01 8b 55 90 01 01 8b 02 0f b7 48 06 39 4d 90 01 01 0f 8d 90 00 } //1
		$a_03_2 = {8b 55 f0 83 c2 01 89 55 90 01 01 8b 45 90 01 01 83 c0 02 89 45 90 01 01 8b 4d 90 01 01 8b 51 90 01 01 83 ea 08 d1 ea 39 55 f0 73 90 01 01 8b 45 90 01 01 0f b7 08 c1 f9 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}