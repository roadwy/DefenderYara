
rule Trojan_Win32_Emotetcrypt_VD_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a 04 38 30 90 01 01 8b 45 90 01 01 8b 5d 90 01 01 3b 75 90 01 01 7c 90 0a 32 00 03 90 02 07 f7 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ca 0f b6 90 02 02 0f b6 90 02 02 03 c1 89 55 90 02 02 33 d2 f7 35 90 02 04 8b 4d 90 02 02 03 55 90 02 02 8a 04 32 02 45 ff 32 04 39 88 07 47 ff 4d 0c 75 90 02 02 5f 5e 5b c9 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}