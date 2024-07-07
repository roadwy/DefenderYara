
rule TrojanSpy_Win32_Bancos_CY{
	meta:
		description = "TrojanSpy:Win32/Bancos.CY,SIGNATURE_TYPE_PEHSTR,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 65 63 75 72 69 70 72 6f 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10
		$a_01_1 = {00 46 54 57 41 52 45 5c 42 00 } //2 䘀坔剁居B
		$a_01_2 = {44 00 4c 00 4c 00 20 00 64 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 } //2 DLL de servi
		$a_01_3 = {47 62 50 6c 75 67 69 6e 53 65 63 4c 6f 63 6b } //1 GbPluginSecLock
		$a_01_4 = {47 62 50 6c 75 67 69 6e 53 65 63 53 74 6f 70 53 63 72 65 65 6e 53 61 76 65 72 } //1 GbPluginSecStopScreenSaver
		$a_01_5 = {47 62 50 6c 75 67 69 6e 53 65 63 53 68 75 74 64 6f 77 6e } //1 GbPluginSecShutdown
		$a_01_6 = {47 62 50 6c 75 67 69 6e 53 65 63 4c 6f 67 6f 66 66 } //1 GbPluginSecLogoff
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}