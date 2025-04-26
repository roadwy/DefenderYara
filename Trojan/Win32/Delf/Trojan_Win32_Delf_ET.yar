
rule Trojan_Win32_Delf_ET{
	meta:
		description = "Trojan:Win32/Delf.ET,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 19 00 00 00 e8 ?? ?? ff ff 8b d0 83 c2 61 8d 45 d8 e8 ?? ?? ff ff ff 75 d8 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba 07 00 00 00 e8 ?? ?? ff ff 8d 45 d4 e8 ?? ?? ff ff ff 75 d4 b8 19 00 00 00 } //1
		$a_03_1 = {8b c6 33 c9 ba 44 00 00 00 e8 ?? ?? ff ff c7 46 2c 01 00 00 00 66 c7 46 30 00 00 68 ?? ?? ?? ?? 56 6a 00 6a 00 6a 40 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}