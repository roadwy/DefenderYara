
rule Virus_Win32_VB_CZ{
	meta:
		description = "Virus:Win32/VB.CZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 63 68 65 69 64 65 6e 70 69 6c 7a } //Scheidenpilz  1
		$a_00_1 = {5c 00 2a 00 2e 00 65 00 78 00 65 00 } //1 \*.exe
		$a_00_2 = {5c 00 2a 00 2e 00 2a 00 } //1 \*.*
		$a_02_3 = {c7 85 50 ff ff ff ?? ?? ?? ?? 6a 08 5e 89 b5 48 ff ff ff 8d 95 48 ff ff ff 8d 4d a8 e8 1e e8 ff ff c7 85 60 ff ff ff ?? ?? ?? ?? 89 b5 58 ff ff ff 8d 95 58 ff ff ff 8d 4d b8 e8 ?? ?? ff ff 8d 45 d4 89 85 70 ff ff ff c7 85 68 ff ff ff 0b 40 00 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}