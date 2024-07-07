
rule MonitoringTool_Win32_KeyloggerOnline{
	meta:
		description = "MonitoringTool:Win32/KeyloggerOnline,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 bd c0 fd ff ff 49 45 46 72 75 } //2
		$a_01_1 = {81 bd c0 fd ff ff 43 68 72 6f 75 } //2
		$a_01_2 = {81 bd c0 fd ff ff 4d 6f 7a 69 75 } //2
		$a_01_3 = {8b 75 10 ad ad c1 e0 10 91 ad c1 e0 18 0b c8 } //2
		$a_01_4 = {4b 65 79 6c 6f 67 67 65 72 4f 6e 6c 69 6e 65 2e 63 6f 6d } //2 KeyloggerOnline.com
		$a_01_5 = {44 69 73 61 62 6c 65 64 20 4b 65 79 6c 6f 67 67 65 72 21 } //1 Disabled Keylogger!
		$a_01_6 = {47 6c 6f 62 61 6c 5c 74 6d 2d } //1 Global\tm-
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}