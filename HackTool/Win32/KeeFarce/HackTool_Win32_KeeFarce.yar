
rule HackTool_Win32_KeeFarce{
	meta:
		description = "HackTool:Win32/KeeFarce,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 00 65 00 65 00 46 00 61 00 72 00 63 00 65 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00 } //1 KeeFarceDLL.dll
		$a_01_1 = {5b 2e 5d 20 49 6e 6a 65 63 74 69 6e 67 20 42 6f 6f 74 73 74 72 61 70 44 4c 4c 20 69 6e 74 6f 20 25 64 } //1 [.] Injecting BootstrapDLL into %d
		$a_01_2 = {6b 65 65 70 61 73 73 5f 65 78 70 6f 72 74 2e 63 73 76 } //1 keepass_export.csv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}