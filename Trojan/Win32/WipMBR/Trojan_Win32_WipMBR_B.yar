
rule Trojan_Win32_WipMBR_B{
	meta:
		description = "Trojan:Win32/WipMBR.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 73 20 2f 62 20 2f 61 3a 2d 44 20 32 3e 6e 75 6c 20 7c 20 66 69 6e 64 73 74 72 20 2d 69 20 64 6f 63 75 6d 65 6e 74 20 32 3e 6e 75 6c 20 3e 3e } //1 /s /b /a:-D 2>nul | findstr -i document 2>nul >>
		$a_03_1 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8a 44 47 fe 88 44 24 08 2c 30 3c 09 77 90 01 01 8d 4b 90 01 01 80 f9 09 77 90 01 01 83 7c 24 0c 09 77 90 01 01 8d 44 24 08 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}