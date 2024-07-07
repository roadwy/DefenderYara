
rule Trojan_Win32_CryptInject_AT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_00_1 = {44 65 63 6f 64 65 50 6f 69 6e 74 65 72 } //1 DecodePointer
		$a_00_2 = {52 65 61 64 45 6e 63 72 79 70 74 65 64 46 69 6c 65 52 61 77 } //1 ReadEncryptedFileRaw
		$a_00_3 = {c7 44 24 08 00 10 00 00 c7 44 24 0c 40 00 00 00 } //1
		$a_02_4 = {88 44 24 4f 8b 44 24 30 8b 4c 24 08 8a 1c 08 8b 44 24 28 32 1c 10 8b 54 24 2c 88 1c 0a 83 c1 01 8b 44 24 34 39 c1 8b 44 24 04 89 4c 24 1c 89 44 24 20 89 7c 24 24 0f 84 90 01 01 ff ff ff e9 90 01 01 ff ff ff 90 00 } //1
		$a_02_5 = {0f b6 c9 8b 74 24 34 8b 7c 24 14 89 0c 24 8a 0c 3e 8b 34 24 01 de 81 e6 ff 00 00 00 8b 5c 24 2c 32 0c 33 8b 74 24 30 88 0c 3e 83 c7 01 8b 4c 24 38 39 cf 8b 4c 24 08 89 4c 24 1c 89 54 24 18 89 7c 24 20 0f 84 90 01 01 ff ff ff e9 90 01 01 ff ff ff 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=4
 
}