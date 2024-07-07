
rule Trojan_Win32_Nebuler_F{
	meta:
		description = "Trojan:Win32/Nebuler.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 45 fc 8b 4d fc 8d 5c 03 01 8b 45 08 83 c7 90 01 01 3b 08 72 84 5e 33 c0 85 db 7e 11 8a c8 80 e9 15 30 8c 05 fc f7 ff ff 40 3b c3 7c ef 53 8d 85 fc f7 ff ff 50 ff 75 10 8b 45 0c 90 00 } //1
		$a_03_1 = {c7 00 77 69 6e 00 8d 48 03 5e e8 90 01 02 00 00 6a 1a 99 5f f7 ff 80 c2 61 88 11 41 4e 75 ec c7 01 33 32 00 00 41 41 5f c7 01 2e 64 6c 6c c6 41 04 00 b0 01 90 00 } //1
		$a_00_2 = {26 76 3d 25 64 26 62 3d 25 64 26 69 64 3d 25 58 26 63 6e 74 3d 25 73 26 71 3d 25 58 } //1 &v=%d&b=%d&id=%X&cnt=%s&q=%X
		$a_01_3 = {6d 33 64 35 72 74 31 30 } //1 m3d5rt10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}