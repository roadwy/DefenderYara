
rule Trojan_Win32_Zlob_gen_L{
	meta:
		description = "Trojan:Win32/Zlob.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 4f 33 c0 8a 44 24 08 57 8b f9 83 fa 04 72 31 f7 d9 83 e1 03 74 0c 2b d1 88 07 83 c7 01 83 e9 01 75 f6 8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06 f3 ab 85 d2 74 0a 88 07 83 c7 01 83 ea 01 75 f6 8b 44 24 08 5f c3 } //10
		$a_00_1 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 } //10
		$a_01_2 = {41 74 74 65 6e 74 69 6f 6e 21 } //1 Attention!
		$a_01_3 = {59 6f 75 20 73 68 6f 75 6c 64 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 70 72 69 6f 72 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 69 6e 67 20 74 68 69 73 20 73 6f 66 74 77 61 72 65 2e 20 52 65 62 6f 6f 74 20 6e 6f 77 3f } //1 You should reboot your computer prior to uninstalling this software. Reboot now?
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 50 72 6f 6a 65 63 74 } //1 Software\NetProject
		$a_00_5 = {25 64 2e 62 61 74 } //1 %d.bat
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=24
 
}