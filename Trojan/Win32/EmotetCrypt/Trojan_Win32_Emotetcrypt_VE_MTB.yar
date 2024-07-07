
rule Trojan_Win32_Emotetcrypt_VE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 11 8b c7 2b 05 90 01 04 03 45 90 01 01 30 90 01 01 47 89 7d 90 01 01 3b 7d 90 01 01 0f 8c 90 0a 32 00 0f b6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 33 d2 f7 f1 90 02 04 03 55 90 02 02 8a 04 32 90 02 04 02 45 90 02 02 32 04 90 02 02 88 07 47 ff 4d 90 02 02 75 90 02 02 5f 5e 5b c9 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}