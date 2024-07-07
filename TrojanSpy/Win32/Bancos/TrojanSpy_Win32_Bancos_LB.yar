
rule TrojanSpy_Win32_Bancos_LB{
	meta:
		description = "TrojanSpy:Win32/Bancos.LB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {7c 65 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 48 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 } //10
		$a_00_1 = {68 6f 6d 65 2e 6a 70 67 00 } //1
		$a_00_2 = {52 65 67 53 76 72 33 32 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 67 6f 6f 67 6c 65 2e 64 6c 6c 20 2f 73 } //1 RegSvr32 C:\WINDOWS\SYSTEM32\google.dll /s
		$a_00_3 = {45 3a 5c 70 72 6f 6a 65 74 6f 73 5c 42 48 4f 42 4a 20 4a 65 72 75 6e 64 69 6f 5c 42 48 4f 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //1 E:\projetos\BHOBJ Jerundio\BHO\_IEBrowserHelper.pas
		$a_00_4 = {45 3a 5c 70 72 6f 6a 65 74 6f 73 5c 42 48 4f 42 4a 20 43 61 72 61 50 72 65 74 61 5c 5f 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 2e 70 61 73 } //1 E:\projetos\BHOBJ CaraPreta\_IEBrowserHelper.pas
		$a_00_5 = {67 6f 6f 67 6c 65 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=12
 
}