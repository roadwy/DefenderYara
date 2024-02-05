
rule Trojan_Win32_Emotetcrypt_VH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 01 30 07 8b 45 90 01 01 3b 75 90 01 01 0f 8c 90 0a 19 00 0f b6 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotetcrypt_VH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 33 d2 f7 f5 90 02 19 8b 44 90 02 02 8b 54 90 02 02 8a 0c 90 02 02 32 0c 90 02 02 40 83 6c 90 02 02 01 88 48 90 02 02 89 44 90 02 02 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}