
rule Trojan_Win32_CryptInject_AK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 e8 fe ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 90 01 01 ff ff ff 8b e5 5d c3 90 00 } //1
		$a_02_1 = {8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 90 01 02 ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 90 01 01 ff ff ff 8b 4d e4 33 cd e8 90 01 03 00 8b e5 5d c3 90 00 } //1
		$a_00_2 = {45 33 c9 81 e5 ff 00 00 00 33 c0 8a 4c 2c 10 03 d9 81 e3 ff 00 00 00 8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c c5 } //1
		$a_02_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_00_4 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_00_5 = {43 00 72 00 79 00 70 00 74 00 41 00 63 00 71 00 75 00 69 00 72 00 65 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 41 00 } //1 CryptAcquireContextA
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}