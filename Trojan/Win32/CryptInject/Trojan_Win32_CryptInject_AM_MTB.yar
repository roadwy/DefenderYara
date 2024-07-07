
rule Trojan_Win32_CryptInject_AM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f8 8b 55 08 89 11 8b 85 90 01 02 ff ff 83 c0 10 50 8b 4d fc 51 6a 00 e8 90 01 04 83 c4 0c 8b 55 f8 52 ff 55 fc 83 c4 04 5f 5e 8b e5 5d c3 90 00 } //1
		$a_02_1 = {8b 45 0c 03 45 08 8b 0d 90 01 03 00 8a 14 08 32 15 90 01 03 00 8b 45 0c 03 45 08 8b 0d 90 01 03 00 88 14 08 83 3d 90 01 03 00 03 76 0b 8b 55 08 83 c2 01 89 55 08 eb 01 cc 81 7d 08 90 01 02 00 00 7e 04 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}