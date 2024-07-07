
rule Trojan_Win32_Emotetcrypt_VV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a 90 02 02 8b 44 90 02 02 30 14 90 02 01 8b 44 90 02 02 45 3b 90 02 01 7c 90 02 05 8b 90 02 03 8a 90 02 03 5f 90 02 02 88 90 02 01 88 90 02 02 5d 59 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}