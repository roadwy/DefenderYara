
rule Trojan_Win32_Emotetcrypt_VK_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_02_0 = {ff d3 50 ff 15 [0-04] 8b 0d [0-04] 89 08 8b 15 [0-04] 89 50 [0-02] 8a 0d [0-04] 8d 55 [0-02] 52 50 57 88 48 [0-02] ff 15 } //1
		$a_02_1 = {8a 06 88 07 8a 46 ?? 88 47 ?? 8a 46 ?? 88 47 ?? 8b 45 ?? 5e 5f c9 c3 } //1
		$a_02_2 = {48 83 c8 fc 40 40 83 f8 [0-02] 7e [0-02] 8b 4d [0-02] 8b 45 [0-02] 51 8d 55 [0-02] 52 56 57 6a 01 57 50 ff 15 [0-04] 85 c0 0f 84 [0-04] ff } //1
		$a_80_3 = {4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 } //LdrFindResource_U  5
		$a_80_4 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //LdrAccessResource  5
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  5
		$a_80_6 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  5
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_80_6  & 1)*5) >=23
 
}
rule Trojan_Win32_Emotetcrypt_VK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //Control_RunDLL  1
		$a_80_1 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //LdrAccessResource  1
		$a_80_2 = {4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 } //LdrFindResource_U  1
		$a_80_3 = {6e 74 64 6c 6c 2e 64 6c 6c } //ntdll.dll  1
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_5 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  1
		$a_02_6 = {68 00 10 00 00 ?? ?? ff ?? 8b ?? ?? ?? 8b ?? ?? ?? 8b ?? 8b ?? c1 ?? ?? 8b ?? f3 ?? 8b ?? 83 ?? ?? f3 a4 8b ?? ?? ?? 8b ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 6a 01 ?? ?? ff 15 } //1
		$a_02_7 = {83 c4 04 50 [0-08] 68 00 10 00 00 ?? ?? ff ?? 8b ?? ?? ?? 8b ?? 8b ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? 8b ?? ?? ?? 83 ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 6a 01 ?? ?? ff 15 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1) >=7
 
}