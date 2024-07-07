
rule Trojan_Win32_Valden_C{
	meta:
		description = "Trojan:Win32/Valden.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 58 50 4f 52 54 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 47 62 50 6c 75 67 69 6e } //1 EXPORT HKCU\Software\GbPlugin
		$a_01_1 = {45 58 50 4f 52 54 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 47 62 41 73 } //1 EXPORT HKCU\Software\GbAs
		$a_01_2 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 50 72 6f 67 72 61 6d 61 73 5c 47 62 50 6c 75 67 69 6e 5c 62 62 2e 67 70 63 } //1 C:\Arquivos de Programas\GbPlugin\bb.gpc
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 47 62 50 6c 75 67 69 6e 5c 62 62 2e 67 70 63 } //1 C:\Program Files\GbPlugin\bb.gpc
		$a_01_4 = {53 79 6e 63 4d 6f 64 65 35 00 } //1 祓据潍敤5
		$a_00_5 = {73 65 6c 66 64 65 73 74 72 75 63 74 00 } //1
		$a_00_6 = {64 61 74 61 3d 68 65 6c 6c 6f 26 75 73 65 72 } //1 data=hello&user
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}