
rule Virus_Win32_Patchload_gen_E{
	meta:
		description = "Virus:Win32/Patchload.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {84 d2 0f 85 a1 00 00 00 85 c9 0f 84 c2 00 00 00 81 f9 55 c6 79 92 0f 84 b6 00 00 00 81 f9 8b b9 b5 c2 0f 84 aa 00 00 00 81 f9 b3 12 23 de 0f 84 9e 00 00 00 81 f9 57 90 1e 4f 0f 84 92 00 00 00 81 f9 0f cb 2e 90 0f 84 86 00 00 00 81 f9 07 39 ef 51 74 7e 81 f9 20 7a 1d c7 74 76 81 f9 bc 5b 0a c5 74 6e } //1
		$a_02_1 = {89 4d d4 81 f9 ?? ?? 00 00 7d 34 8b 14 8d ?? ?? 00 10 89 55 e0 8b c2 c1 e8 16 c1 e2 0a 0b c2 89 45 e0 33 c1 89 45 e0 2b c1 89 45 e0 8b d0 } //1
		$a_03_2 = {89 55 d4 81 fa ?? ?? 00 00 7d 22 8b 0c 95 ?? ?? 00 10 89 4d ?? 8b c1 c1 e0 ?? c1 e9 ?? 0b c1 89 45 ?? 2b c2 89 45 ?? 89 04 96 42 eb d3 ff d6 } //1
		$a_02_3 = {ff 14 85 f8 db 00 10 eb ?? 8b d0 c1 e2 ?? c1 e8 ?? 0b c2 89 45 ?? 05 ?? ?? 00 00 89 45 ?? 0f b6 c9 03 c1 e9 ?? ff ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}