
rule Trojan_Win32_Emotetcrypt_VG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d6 53 53 ff d6 8b 45 90 02 02 8a 0c 90 02 02 02 4d 90 02 02 8b 45 90 02 02 8b 55 90 02 02 32 0c 90 02 02 88 08 40 ff 4d 90 02 02 89 45 90 02 02 0f 85 90 02 04 5f 5e 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotetcrypt_VG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 90 01 01 8b d5 2b 15 90 01 04 45 03 c2 8b 15 90 01 04 8a 0c 90 01 01 30 90 01 01 3b 6c 90 01 02 0f 8c 90 00 } //01 00 
		$a_02_1 = {0f b6 c2 8a 90 01 02 30 90 01 02 b9 90 01 04 8b 7d 90 01 01 47 89 7d 90 01 01 3b 7d 90 01 01 7c 90 0a 32 00 03 90 02 0f f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}