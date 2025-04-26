
rule Trojan_Win32_Delf_LL{
	meta:
		description = "Trojan:Win32/Delf.LL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 1f 00 0f 00 e8 ?? ?? ff ff a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 75 ?? 68 ?? ?? 41 00 6a 04 6a 00 6a 04 6a 00 6a ff e8 } //1
		$a_03_1 = {8b 10 33 c9 89 08 8b c2 e8 ?? ?? ff ff c3 8b c0 1d 00 00 00 08 33 41 00 d8 34 41 00 00 33 41 00 } //1
		$a_03_2 = {54 4e 74 48 6f 6f 6b [0-01] 43 6c 61 73 73 } //1
		$a_03_3 = {68 6f 6f 6b [0-01] 44 6c 6c 2e 64 6c 6c [0-04] 45 6e 64 48 6f 6f 6b [0-04] 53 74 61 72 74 48 6f 6f 6b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}