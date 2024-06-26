
rule Trojan_Win32_TrickbotCrypt_SV_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 57 56 b8 90 01 01 00 00 00 89 44 24 90 01 01 b9 90 01 04 89 4c 24 90 01 01 b8 90 01 01 00 00 00 89 44 24 90 01 01 8d 15 90 01 04 89 14 24 e8 90 01 04 83 c4 90 01 01 33 c0 c3 90 00 } //01 00 
		$a_03_1 = {53 56 8b 4c 24 90 01 01 8b 54 24 90 01 01 8b 74 24 90 01 01 8b 7c 24 90 01 01 85 d2 74 90 01 01 ac 52 30 07 5a 4a 47 e2 90 01 01 5e 5b 33 c0 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickbotCrypt_SV_MTB_2{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 90 01 01 68 90 01 02 00 00 ff 15 90 01 04 68 90 01 04 6a 65 6a 00 ff 15 90 01 04 89 45 90 01 01 8b 45 90 01 01 50 6a 00 ff 15 90 01 04 89 45 90 01 01 8b 4d 90 01 01 51 6a 00 ff 15 90 01 04 89 45 90 01 01 8b 55 90 01 01 52 ff 15 90 00 } //01 00 
		$a_03_1 = {75 04 32 c0 eb 90 01 01 8b 4d 90 01 01 8b 11 52 8b 45 90 01 01 50 8b 4d 90 01 01 51 6a 00 6a 01 6a 00 8b 55 90 01 01 52 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickbotCrypt_SV_MTB_3{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ed ff 15 90 01 04 85 c0 75 90 01 01 8b 44 24 90 01 01 6a 40 68 00 10 00 00 50 53 ff 15 90 01 04 8b e8 90 00 } //01 00 
		$a_03_1 = {33 c0 8b 0d 90 01 04 88 04 01 40 3d 90 01 02 00 00 7c 90 00 } //01 00 
		$a_03_2 = {83 c4 04 89 b4 24 90 01 02 00 00 89 9c 24 90 01 02 00 00 88 9c 24 90 01 02 00 00 39 bc 24 90 01 02 00 00 72 10 8b 8c 24 90 01 02 00 00 51 e8 90 01 02 00 00 83 c4 04 89 b4 24 90 01 02 00 00 89 9c 24 90 01 02 00 00 88 9c 24 90 01 01 00 00 00 39 bc 24 90 01 01 00 00 00 72 90 01 01 8b 54 24 90 01 01 52 e8 90 01 04 83 c4 04 89 b4 24 90 01 01 00 00 00 89 5c 24 90 01 01 88 5c 24 90 01 01 39 bc 24 90 01 01 00 00 00 72 10 8b 84 24 90 01 01 00 00 00 50 e8 90 01 02 00 00 83 c4 04 89 b4 24 90 01 01 00 00 00 89 9c 24 90 01 01 00 00 00 88 9c 24 90 01 01 00 00 00 39 bc 24 90 01 02 00 00 0f 82 90 01 02 00 00 8b 8c 24 90 01 02 00 00 51 e9 90 01 02 00 00 ff d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}