
rule Trojan_Win32_Emotetcrypt_EC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 01 8b 4c 24 90 01 01 0f b6 11 03 c2 99 b9 74 02 00 00 f7 f9 a1 90 01 04 88 54 24 11 8b 15 90 00 } //1
		$a_03_1 = {0f b6 54 24 11 8b 0d 90 01 04 8a 14 0a 8b 45 08 30 14 06 46 3b 75 0c 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}