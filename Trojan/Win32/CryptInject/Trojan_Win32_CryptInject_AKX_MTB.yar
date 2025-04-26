
rule Trojan_Win32_CryptInject_AKX_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 b8 8b 45 f0 8d 1c 02 8b 55 ec 8b 45 f0 01 d0 0f b6 30 8b 4d f0 ba 4f ec c4 4e 89 c8 f7 e2 89 d0 c1 e8 03 6b c0 1a 29 c1 89 c8 0f b6 44 05 96 31 f0 88 03 } //2
		$a_01_1 = {4a 4b 48 21 78 6a 2b 74 76 32 3c 3f 56 57 45 3f 2b 74 36 76 3f 5f 72 5a 2b } //1 JKH!xj+tv2<?VWE?+t6v?_rZ+
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}