
rule Trojan_Win32_Emotetcrypt_VY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 8b d8 8b 0d 90 02 04 33 d2 8b c1 f7 f3 03 55 90 01 01 8a 04 32 8b 55 90 01 01 32 04 90 01 01 8b 55 90 01 01 88 04 90 01 01 ff 05 90 02 04 39 3d 90 02 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VY_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 8a 90 01 02 90 17 03 01 01 01 30 32 33 90 01 02 83 90 01 03 01 75 90 01 01 8b 90 01 03 8a 90 01 03 8a 90 01 03 5f 90 01 02 88 90 02 02 88 90 02 02 5b 83 90 01 02 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}