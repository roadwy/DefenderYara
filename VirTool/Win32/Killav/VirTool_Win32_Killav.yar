
rule VirTool_Win32_Killav{
	meta:
		description = "VirTool:Win32/Killav,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {41 6e 74 69 4b 61 73 70 65 72 73 6b 79 20 } //1 AntiKaspersky 
		$a_00_1 = {42 75 69 6c 64 3a 20 } //1 Build: 
		$a_00_2 = {6b 61 73 32 6b 2c 20 74 6f 6f 6c 7a 2e 70 79 63 63 78 61 6b 2e 63 6f 6d } //1 kas2k, toolz.pyccxak.com
		$a_00_3 = {45 72 72 6f 72 20 4e 31 21 2c 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 4e 55 4c 4c 2e } //1 Error N1!, CommandLine NULL.
		$a_00_4 = {46 69 6c 65 20 43 72 79 70 74 65 64 21 } //1 File Crypted!
		$a_01_5 = {46 55 43 4b } //1 FUCK
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}