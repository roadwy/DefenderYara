
rule TrojanSpy_Win32_Bancos_AFM{
	meta:
		description = "TrojanSpy:Win32/Bancos.AFM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b c6 8b 4d f8 0f b7 44 41 fe 33 d0 8b c2 66 89 45 ee 8d 45 e4 0f b7 55 ee e8 } //1
		$a_09_1 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 37 00 78 00 65 00 5c 00 69 00 64 00 2e 00 73 00 79 00 73 00 } //1 c:\win7xe\id.sys
		$a_03_2 = {43 3a 5c 77 69 6e 37 78 65 5c 77 69 6e [0-05] 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_09_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}