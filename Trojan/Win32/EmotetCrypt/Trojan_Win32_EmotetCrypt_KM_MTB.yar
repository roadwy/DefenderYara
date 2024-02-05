
rule Trojan_Win32_EmotetCrypt_KM_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 0f b6 4d 90 01 01 8a 0c 11 30 08 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_KM_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 29 09 00 00 e8 90 01 04 83 c4 04 a1 90 01 04 8b 0d 90 01 04 8d 94 01 90 01 04 2b 15 90 01 05 15 90 01 04 89 15 90 01 04 a1 90 01 04 2d 29 09 00 00 a3 90 01 04 8b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 3b 05 90 01 04 72 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}