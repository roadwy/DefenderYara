
rule Trojan_Win32_Emotetcrypt_VL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 90 02 04 f7 f9 90 02 19 0f b6 90 02 04 a1 90 02 04 8a 0c 90 02 02 8b 44 90 02 02 30 0c 28 8b 44 90 02 02 45 3b e8 0f 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VL_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //Control_RunDLL  1
		$a_80_1 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //LdrAccessResource  1
		$a_80_2 = {4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 } //LdrFindResource_U  1
		$a_80_3 = {6e 74 64 6c 6c 2e 64 6c 6c } //ntdll.dll  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  1
		$a_80_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_02_7 = {8b cf c1 e9 90 01 01 8b c7 c1 e8 90 01 01 83 e0 01 83 e1 01 8d 0c 48 8b c7 c1 e8 90 01 01 8d 04 48 8b 04 85 90 01 04 f7 c7 00 00 00 04 90 01 02 0d 90 01 04 8d 4d 90 01 01 51 50 56 ff 32 ff 15 90 01 04 f7 d8 1b c0 90 02 02 f7 d8 90 02 03 c2 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}