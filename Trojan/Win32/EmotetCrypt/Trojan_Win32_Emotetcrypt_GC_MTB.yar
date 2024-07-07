
rule Trojan_Win32_Emotetcrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b ca 2b 0d 90 01 04 2b 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 03 0d 90 01 04 03 d1 2b 15 90 01 04 2b 15 90 01 04 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 8b 35 90 00 } //1
		$a_03_1 = {0f b6 04 10 33 d2 0f b6 0c 31 03 c1 b9 90 01 04 f7 f1 8b 45 fc 03 55 f8 8b 4d f0 0f b6 04 02 8b 55 ec 30 04 0a 41 89 4d f0 3b cf b9 90 01 04 72 90 00 } //1
		$a_03_2 = {03 d0 2b 15 90 01 04 2b 15 90 01 04 03 15 90 01 04 8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 8b 35 90 01 04 0f af 35 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}