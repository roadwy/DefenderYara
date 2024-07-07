
rule Trojan_Win32_Emotet_I_MTB{
	meta:
		description = "Trojan:Win32/Emotet.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ff 5f 5d c3 90 0a 4f 00 b8 90 01 04 31 0d 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 01 04 8b ff 5f 5d c3 90 00 } //1
		$a_02_1 = {8b 55 fc 8d 84 02 90 01 04 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 90 01 04 8b 55 08 89 0a 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_I_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {50 53 ff 75 f8 68 01 68 00 00 ff 75 fc ff 55 f0 85 c0 74 90 01 01 6a 40 68 00 10 00 00 ff 75 0c 56 ff 55 c0 ff 75 0c 8b f8 ff 75 08 57 ff 55 e0 83 c4 0c 8d 45 0c ff 75 0c 50 57 56 53 56 ff 75 f4 ff 55 e4 f7 d8 1b c0 23 c7 5f 5e 5b c9 c3 90 00 } //1
		$a_00_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_00_2 = {53 65 74 55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //1 SetUnhandledExceptionFilter
		$a_02_3 = {89 55 08 8b 54 91 08 89 54 99 08 8b 5d 08 89 55 fc 8b 55 10 89 54 99 08 8b 5d fc 03 da 23 d8 8a 54 99 08 32 57 06 ff 4d f8 88 56 06 74 90 01 01 8b 55 14 e9 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}