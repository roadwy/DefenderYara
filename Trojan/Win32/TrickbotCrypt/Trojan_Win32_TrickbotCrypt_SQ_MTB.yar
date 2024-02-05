
rule Trojan_Win32_TrickbotCrypt_SQ_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 d2 8d 41 90 01 01 f7 f7 6a 00 8b f2 33 d2 89 75 90 01 01 6a 00 0f b6 04 1e 03 45 90 01 01 f7 f7 0f b6 04 1e 89 55 90 01 01 8a 0c 1a 88 04 1a 88 0c 1e 0f b6 c1 0f b6 0c 1a 33 d2 03 c1 f7 f7 8b f2 ff 15 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 0f b6 04 0a 32 04 1e 88 01 41 ff 4d 90 01 01 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickbotCrypt_SQ_MTB_2{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff d3 8b d0 8d 4d 90 01 01 ff d6 50 6a 90 01 01 ff d3 8b d0 8d 4d 90 01 01 ff d6 50 ff d7 8b d0 8d 4d 90 01 01 ff d6 50 6a 90 01 01 ff d3 90 00 } //02 00 
		$a_03_1 = {50 6a 00 e8 90 01 04 89 85 90 01 04 ff 15 90 01 04 8b 8d 90 01 04 8d 95 90 01 04 8d 85 90 01 04 89 0d 90 01 04 52 50 8d 4d 90 01 01 8d 55 90 01 01 51 8d 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}