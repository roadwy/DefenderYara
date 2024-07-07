
rule TrojanDropper_Win32_Delf_CZ{
	meta:
		description = "TrojanDropper:Win32/Delf.CZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 04 00 00 00 2e 65 78 65 } //1
		$a_03_1 = {84 c0 74 45 6a 01 a1 90 01 04 e8 90 01 02 ff ff 50 e8 90 01 02 ff ff a1 90 01 04 e8 90 01 02 ff ff 33 db eb 17 43 83 fb 64 7d 1f 6a 64 e8 90 00 } //1
		$a_03_2 = {33 db 8b c3 99 f7 3d 90 01 04 a1 90 01 04 0f b6 04 10 8b 15 90 01 04 0f b6 14 1a 2b d0 81 c2 00 01 00 00 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 a1 90 01 04 88 14 18 43 90 01 01 75 c0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}