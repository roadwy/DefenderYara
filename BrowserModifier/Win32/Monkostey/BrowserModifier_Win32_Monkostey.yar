
rule BrowserModifier_Win32_Monkostey{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 68 74 74 70 3a 2f 2f 75 6e 69 6e 73 74 61 6c 6c 2e 6d 79 73 61 66 65 73 61 76 69 6e 67 73 2e 63 6f 6d } //1 explorer.exe http://uninstall.mysafesavings.com
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 4c 6f 67 67 65 72 5c 77 69 6e 6c 6f 67 67 65 72 2e 65 78 65 } //1 Microsoft\WindowsLogger\winlogger.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 79 53 61 66 65 53 61 76 69 6e 67 73 } //1 Software\MySafeSavings
		$a_01_3 = {67 72 69 6c 00 46 69 6e 64 69 } //1 牧汩䘀湩楤
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Monkostey_2{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 53 33 db 83 7d 08 02 c6 45 90 01 01 65 c6 45 90 01 01 6e c6 45 90 01 01 4d c6 45 90 01 01 75 c6 45 90 01 01 52 c6 45 90 01 01 61 90 00 } //1
		$a_03_1 = {8d 45 d4 50 6a 02 53 89 75 d4 c7 45 90 01 01 03 00 00 00 89 75 90 01 01 89 75 90 01 01 89 75 90 01 01 ff 15 90 01 04 53 8b f0 ff d7 eb 90 00 } //1
		$a_03_2 = {ff d7 53 6a 26 bd 90 01 04 55 53 ff d6 68 90 01 04 55 ff d7 53 6a 23 bd 90 01 04 55 53 ff d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule BrowserModifier_Win32_Monkostey_3{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 73 58 6a 69 66 89 90 01 02 58 6a 4d 66 89 90 01 02 58 6a 61 66 89 90 01 02 58 66 89 90 01 02 6a 53 33 c0 66 89 90 01 02 58 6a 66 90 00 } //1
		$a_03_1 = {0f b7 08 66 83 f9 2d 74 90 01 01 66 83 f9 2f 0f 90 01 02 00 00 00 6a 73 59 6a 61 66 89 4d 90 01 01 66 89 4d 90 01 01 59 6a 6d 66 89 4d 90 01 01 59 66 89 4d 90 01 01 33 c9 6a 73 90 00 } //1
		$a_03_2 = {c7 46 10 04 00 00 00 89 5e 14 89 5e 18 89 5e 1c 89 5e 20 89 5d fc 68 08 02 00 00 8d 46 3c 53 50 c7 90 01 04 00 88 5e 28 89 5e 2c c7 46 34 e8 03 00 00 89 5e 38 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule BrowserModifier_Win32_Monkostey_4{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 53 65 72 76 65 72 } //1 ProxyServer
		$a_01_1 = {6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 } //1 network.proxy.type
		$a_01_2 = {56 77 69 6e 5f 69 6f 63 70 5f 69 6f 5f 73 65 72 76 69 63 65 40 } //1 Vwin_iocp_io_service@
		$a_01_3 = {56 63 6f 6e 6e 65 63 74 69 6f 6e 40 70 72 6f 78 79 40 } //1 Vconnection@proxy@
		$a_01_4 = {68 74 74 70 3d 25 73 3a 25 73 00 00 58 58 58 00 48 4f 53 54 00 00 00 00 55 73 65 72 2d 41 67 65 6e 74 00 00 31 30 30 00 73 65 72 76 69 63 65 } //1
		$a_01_5 = {46 44 66 62 49 44 } //1 FDfbID
		$a_03_6 = {83 7d 08 02 8b 45 0c c6 45 90 01 01 6f c6 45 90 01 01 6e c6 45 90 01 01 75 c6 45 90 01 01 46 c6 45 90 01 01 00 90 00 } //1
		$a_01_7 = {2e 3f 41 56 43 46 69 6e 64 69 6e 67 44 69 73 63 6f 75 6e 74 41 70 70 40 40 } //2 .?AVCFindingDiscountApp@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*2) >=5
 
}
rule BrowserModifier_Win32_Monkostey_5{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 00 69 00 6e 00 64 00 69 00 6e 00 67 00 2e 00 64 00 69 00 73 00 63 00 6f 00 75 00 6e 00 74 00 } //1 finding.discount
		$a_03_1 = {64 00 62 00 67 00 2e 00 70 00 68 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4d 00 61 00 69 00 6e 00 44 00 6c 00 67 00 53 00 74 00 61 00 72 00 74 00 26 00 49 00 45 00 3d 00 90 01 06 26 00 4f 00 53 00 3d 00 90 01 06 26 00 74 00 65 00 73 00 74 00 3d 00 90 02 06 26 00 55 00 73 00 65 00 72 00 49 00 64 00 3d 00 90 00 } //1
		$a_01_2 = {72 00 61 00 74 00 69 00 6e 00 67 00 73 00 2f 00 72 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f 00 63 00 6d 00 64 00 3d 00 67 00 65 00 74 00 26 00 69 00 64 00 3d 00 } //1 ratings/rate.php?cmd=get&id=
		$a_01_3 = {73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 64 00 65 00 62 00 75 00 67 00 68 00 65 00 6c 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 softwaredebughelp.com
		$a_01_4 = {53 00 61 00 66 00 65 00 53 00 61 00 76 00 69 00 6e 00 67 00 73 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 61 00 74 00 } //10 SafeSavings\config.dat
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=14
 
}