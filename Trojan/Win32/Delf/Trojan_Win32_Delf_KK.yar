
rule Trojan_Win32_Delf_KK{
	meta:
		description = "Trojan:Win32/Delf.KK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {c2 08 00 53 a1 ?? ?? ?? ?? 83 38 00 74 ?? 8b 1d ?? ?? ?? ?? 8b 1b ff d3 5b c3 ?? 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 } //1
		$a_00_1 = {5b 63 72 61 7a 69 69 69 } //1 [craziii
		$a_00_2 = {3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 70 61 64 } //1 :\Arquivos de programas\Scpad
		$a_00_3 = {5c 77 69 6e 64 6f 77 73 5c 6b 69 6c 69 6e 68 2e 74 78 74 } //1 \windows\kilinh.txt
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}