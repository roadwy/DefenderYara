
rule Trojan_Win32_Emotetcrypt_VS_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 02 02 8b 0d 90 02 04 8b 44 90 02 04 8a 14 90 02 02 30 14 90 02 02 8b 44 90 02 02 45 3b 90 02 02 7c 87 8b 90 02 04 8a 90 02 04 5f 88 90 02 02 5b 5e 88 90 02 02 5d 59 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}