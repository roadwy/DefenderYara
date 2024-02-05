
rule Trojan_Win32_Icedidcrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/Icedidcrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 03 41 88 01 4d 03 cd 0f b6 8d 90 01 04 49 03 dd c7 85 90 01 08 41 03 d5 8b 85 90 01 04 8b 85 90 01 04 03 c1 89 85 90 01 04 0f b6 8d 90 01 04 c7 85 90 01 08 8b 85 90 01 04 8b 85 90 00 } //0a 00 
		$a_02_1 = {03 c2 89 85 90 01 04 0f b7 85 90 01 04 8a 4c 04 90 01 01 42 88 0c 12 89 b5 90 01 04 8b 85 90 01 04 8b 85 90 01 04 03 c2 41 03 d5 3b 15 90 01 04 89 85 90 01 04 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}