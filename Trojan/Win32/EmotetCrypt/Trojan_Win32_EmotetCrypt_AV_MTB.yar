
rule Trojan_Win32_EmotetCrypt_AV_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8a 8d 90 01 04 0f b6 84 05 90 01 04 30 04 3e 46 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AV_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_AV_MTB_3{
	meta:
		description = "Trojan:Win32/EmotetCrypt.AV!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d be ac 00 00 a3 9c 63 00 10 } //02 00 
		$a_01_1 = {8b 45 08 8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}