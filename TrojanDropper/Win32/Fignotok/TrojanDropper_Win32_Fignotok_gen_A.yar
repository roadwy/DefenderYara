
rule TrojanDropper_Win32_Fignotok_gen_A{
	meta:
		description = "TrojanDropper:Win32/Fignotok.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_1 = {53 62 69 65 44 6c 6c } //1 SbieDll
		$a_00_2 = {25 73 5c 25 73 2e 65 78 65 } //1 %s\%s.exe
		$a_03_3 = {57 69 6e 64 6f 77 73 20 [0-05] 50 68 6f 74 6f 20 47 61 6c 6c 65 72 79 } //1
		$a_01_4 = {50 69 63 74 75 72 65 20 63 61 6e 20 6e 6f 74 20 62 65 20 64 69 73 70 6c 61 79 65 64 2e } //1 Picture can not be displayed.
		$a_02_5 = {43 3a 5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c [0-08] 5c 43 6f 64 65 5c 6d 61 69 6e 5c 64 77 6e 5c 52 65 6c 65 61 73 65 5c 64 77 6e 2e 70 64 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}