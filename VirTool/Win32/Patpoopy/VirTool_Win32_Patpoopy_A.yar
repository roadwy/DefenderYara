
rule VirTool_Win32_Patpoopy_A{
	meta:
		description = "VirTool:Win32/Patpoopy.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {50 75 70 79 50 61 63 6b 61 67 65 4c 6f 61 64 65 72 } //PupyPackageLoader  01 00 
		$a_80_1 = {50 75 70 79 50 61 63 6b 61 67 65 46 69 6e 64 65 72 } //PupyPackageFinder  01 00 
		$a_80_2 = {72 65 67 69 73 74 65 72 5f 70 75 70 79 69 6d 70 6f 72 74 65 72 } //register_pupyimporter  01 00 
		$a_80_3 = {70 75 70 79 5f 61 64 64 5f 70 61 63 6b 61 67 65 } //pupy_add_package  01 00 
		$a_80_4 = {6e 65 74 77 6f 72 6b 2e 6c 69 62 2e 73 74 72 65 61 6d 73 2e 50 75 70 79 53 6f 63 6b 65 74 53 74 72 65 61 6d } //network.lib.streams.PupySocketStream  01 00 
		$a_80_5 = {70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 } //pupy_credentials  01 00 
		$a_80_6 = {70 75 70 79 2e 6d 65 6d 69 6d 70 6f 72 74 65 72 2e 63 74 79 70 65 73 } //pupy.memimporter.ctypes  01 00 
		$a_80_7 = {70 75 70 79 2e 6d 61 6e 61 67 65 72 } //pupy.manager  00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Patpoopy_A_2{
	meta:
		description = "VirTool:Win32/Patpoopy.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 5f 70 75 70 79 69 6d 70 6f 72 74 65 72 5f 64 6c 6c 73 28 } //01 00  __pupyimporter_dlls(
		$a_01_1 = {70 75 70 79 3a 2f 2f 28 } //01 00  pupy://(
		$a_01_2 = {70 75 70 79 69 7a 65 64 3a 20 7b 7d 52 65 } //01 00  pupyized: {}Re
		$a_01_3 = {50 75 70 79 20 63 6f 6e 6e 65 63 74 65 64 3a } //01 00  Pupy connected:
		$a_03_4 = {70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 2e 70 79 65 90 02 10 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 90 00 } //01 00 
		$a_01_5 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6e 31 6e 6a 34 73 65 63 2f 70 75 70 79 } //01 00  github.com/n1nj4sec/pupy
		$a_01_6 = {70 75 70 79 2d 63 6c 69 65 6e 74 2d 7b 7d 2d 7b 7d 2d 64 65 62 75 67 2e 6c 6f 67 } //01 00  pupy-client-{}-{}-debug.log
		$a_01_7 = {6e 65 74 77 6f 72 6b 2e 6c 69 62 2e 73 74 72 65 61 6d 73 2e 50 75 70 79 53 6f 63 6b 65 74 53 74 72 65 61 6d } //00 00  network.lib.streams.PupySocketStream
	condition:
		any of ($a_*)
 
}