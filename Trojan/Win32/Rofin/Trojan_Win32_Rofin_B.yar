
rule Trojan_Win32_Rofin_B{
	meta:
		description = "Trojan:Win32/Rofin.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 00 4f 00 55 00 53 00 45 00 48 00 4f 00 4f 00 4b 00 2e 00 44 00 4c 00 4c 00 } //1 MOUSEHOOK.DLL
		$a_01_1 = {45 00 79 00 6f 00 6f 00 53 00 65 00 63 00 68 00 65 00 6c 00 70 00 65 00 72 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 EyooSechelper2.dll
		$a_01_2 = {62 00 73 00 6f 00 6f 00 61 00 2e 00 64 00 6c 00 6c 00 } //1 bsooa.dll
		$a_01_3 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 68 00 6f 00 6f 00 6b 00 2e 00 64 00 6c 00 6c 00 } //1 Desktophook.dll
		$a_01_4 = {66 61 6b 65 55 72 6c 3a } //1 fakeUrl:
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 70 69 64 20 25 64 } //1 taskkill /pid %d
		$a_01_6 = {5c 5c 2e 5c 46 69 78 54 6f 6f 6c } //1 \\.\FixTool
		$a_01_7 = {54 4f 4d 4d 41 4f 2e 73 79 73 } //1 TOMMAO.sys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}
rule Trojan_Win32_Rofin_B_2{
	meta:
		description = "Trojan:Win32/Rofin.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 44 52 56 44 49 52 23 5a 57 65 62 4e 64 73 2e 73 79 73 } //1 #DRVDIR#ZWebNds.sys
		$a_01_1 = {23 46 30 30 31 23 } //1 #F001#
		$a_01_2 = {63 3a 2f 77 69 6e 64 6f 77 73 2f 61 78 30 31 2e 64 61 30 } //1 c:/windows/ax01.da0
		$a_01_3 = {75 6e 69 63 6f 6e 66 69 2e 64 61 74 } //1 uniconfi.dat
		$a_01_4 = {7b 41 30 39 41 30 31 46 46 2d 31 44 42 43 2d 34 30 30 43 2d 38 31 33 32 2d 35 34 46 41 34 44 42 45 34 45 39 36 7d 3b 7b 35 32 34 46 39 34 43 44 2d 37 31 43 42 2d 34 43 43 44 2d 38 31 42 31 2d 35 38 46 34 46 36 46 35 31 42 46 46 7d 3b } //1 {A09A01FF-1DBC-400C-8132-54FA4DBE4E96};{524F94CD-71CB-4CCD-81B1-58F4F6F51BFF};
		$a_01_5 = {68 74 74 70 3a 2f 2f 6c 6f 67 2e 73 6f 6f 6d 65 6e 67 2e 63 6f 6d 2f 77 62 2f 6a 64 71 2f 3f 6d 61 63 3d 25 73 } //1 http://log.soomeng.com/wb/jdq/?mac=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}