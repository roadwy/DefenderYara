
rule TrojanSpy_Win32_Wedots_A{
	meta:
		description = "TrojanSpy:Win32/Wedots.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 73 25 64 5f 25 73 48 44 5f 25 73 2e 70 6c 6b } //1 %s%d_%sHD_%s.plk
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 65 70 6f 73 74 62 61 6e 6b 2e 63 6f 2e 6b 72 2f 00 68 74 74 70 3a 2f 2f 6b 66 63 63 2e 63 6f 6d 2f 00 } //1
		$a_01_2 = {5c 70 72 6f 66 69 6c 65 73 2e 70 62 6b } //1 \profiles.pbk
		$a_01_3 = {66 72 6f 6d 33 5f 64 6f 77 6e 2d 2d 2d 2d 2d 2d 2d 2d 00 } //1
		$a_01_4 = {c6 44 24 14 73 c6 44 24 15 74 c6 44 24 16 65 88 44 24 17 c6 44 24 18 5f c6 44 24 19 64 c6 44 24 1a 6f c6 44 24 1b 77 c6 44 24 1c 6e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}