
rule Trojan_Win32_Emotetcrypt_VB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 03 c2 0f b6 54 24 90 01 01 8a 14 32 30 10 3b 4c 24 90 01 01 89 4c 24 90 01 01 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotetcrypt_VB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 08 68 90 02 04 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 81 ec 4c 01 00 00 53 56 57 89 65 f8 c7 45 fc 90 02 04 8b 5d 08 b9 3e 00 00 00 33 c0 8d bd 90 02 04 f3 ab 8d 85 90 02 04 33 ff 50 53 89 bd 90 02 04 89 bd 90 02 04 89 bd 90 02 04 89 bd 90 02 04 89 bd 90 02 04 89 bd 90 02 04 e8 90 02 04 85 c0 0f 84 90 02 04 0f bf 90 02 05 8b c8 33 d2 d1 e9 c1 e8 08 23 c8 83 e1 01 66 81 90 02 05 4c 01 0f 94 c2 84 ca 0f 84 90 02 04 8d 85 90 02 04 8d 8d 90 02 04 50 51 ff 15 90 00 } //01 00 
		$a_00_1 = {6a 40 68 00 10 00 00 51 6a 00 ff 15 } //01 00 
		$a_00_2 = {5f 5e 64 89 0d 00 00 00 00 5b 8b e5 5d c2 0c 00 } //02 00 
		$a_80_3 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //RtlMoveMemory  02 00 
		$a_80_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  02 00 
		$a_80_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  00 00 
	condition:
		any of ($a_*)
 
}