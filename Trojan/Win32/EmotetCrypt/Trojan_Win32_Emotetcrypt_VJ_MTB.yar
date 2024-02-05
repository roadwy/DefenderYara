
rule Trojan_Win32_Emotetcrypt_VJ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c7 2b 05 90 02 04 47 03 c8 0f b6 c3 8b 1d 90 02 04 8a 04 90 02 01 30 01 8b 4d 90 02 01 3b fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotetcrypt_VJ_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c3 99 b9 90 02 04 f7 90 02 02 88 90 02 32 8b 55 90 02 02 81 e2 ff 00 00 00 8b 45 90 02 02 03 45 90 02 02 8b 0d 90 02 04 8a 00 32 04 11 8b 4d 90 02 02 03 4d 90 02 02 88 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}