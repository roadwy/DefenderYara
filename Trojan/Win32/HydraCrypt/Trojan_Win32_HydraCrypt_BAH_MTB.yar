
rule Trojan_Win32_HydraCrypt_BAH_MTB{
	meta:
		description = "Trojan:Win32/HydraCrypt.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {88 0c 10 0f b6 55 ff 8b 45 f8 0f b6 0c 10 0f b6 55 fe 8b 45 f8 0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 e9 } //02 00 
		$a_01_1 = {6a 04 68 00 30 00 00 6a 75 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}