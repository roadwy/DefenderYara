
rule Trojan_Win32_Emotetcrypt_VK_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d3 50 ff 15 90 02 04 8b 0d 90 02 04 89 08 8b 15 90 02 04 89 50 90 02 02 8a 0d 90 02 04 8d 55 90 02 02 52 50 57 88 48 90 02 02 ff 15 90 00 } //01 00 
		$a_02_1 = {8a 06 88 07 8a 46 90 01 01 88 47 90 01 01 8a 46 90 01 01 88 47 90 01 01 8b 45 90 01 01 5e 5f c9 c3 90 00 } //01 00 
		$a_02_2 = {48 83 c8 fc 40 40 83 f8 90 02 02 7e 90 02 02 8b 4d 90 02 02 8b 45 90 02 02 51 8d 55 90 02 02 52 56 57 6a 01 57 50 ff 15 90 02 04 85 c0 0f 84 90 02 04 ff 90 00 } //05 00 
		$a_80_3 = {4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 } //LdrFindResource_U  05 00 
		$a_80_4 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //LdrAccessResource  05 00 
		$a_80_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  05 00 
		$a_80_6 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotetcrypt_VK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //Control_RunDLL  01 00 
		$a_80_1 = {4c 64 72 41 63 63 65 73 73 52 65 73 6f 75 72 63 65 } //LdrAccessResource  01 00 
		$a_80_2 = {4c 64 72 46 69 6e 64 52 65 73 6f 75 72 63 65 5f 55 } //LdrFindResource_U  01 00 
		$a_80_3 = {6e 74 64 6c 6c 2e 64 6c 6c } //ntdll.dll  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_5 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  01 00 
		$a_02_6 = {68 00 10 00 00 90 01 02 ff 90 01 01 8b 90 01 03 8b 90 01 03 8b 90 01 01 8b 90 01 01 c1 90 01 02 8b 90 01 01 f3 90 01 01 8b 90 01 01 83 90 01 02 f3 a4 8b 90 01 03 8b 90 01 03 90 01 01 8d 90 01 03 90 01 03 6a 01 90 01 02 ff 15 90 00 } //01 00 
		$a_02_7 = {83 c4 04 50 90 02 08 68 00 10 00 00 90 01 02 ff 90 01 01 8b 90 01 03 8b 90 01 01 8b 90 01 06 e8 90 01 04 8b 90 01 03 8b 90 01 03 83 90 01 03 8d 90 01 06 6a 01 90 01 02 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}