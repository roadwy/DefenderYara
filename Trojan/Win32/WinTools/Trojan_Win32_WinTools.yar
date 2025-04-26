
rule Trojan_Win32_WinTools{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 53 4b 5f 45 4e 41 42 4c 45 5f 48 4f 4d 45 50 41 47 45 } //1 ASK_ENABLE_HOMEPAGE
		$a_01_1 = {41 64 53 57 6e 64 50 72 6f 63 } //1 AdSWndProc
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 54 6f 6f 6c 73 } //1 Software\WinTools
		$a_01_3 = {57 54 6f 6f 6c 73 42 2e 64 6c 6c } //1 WToolsB.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_WinTools_2{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {57 65 62 53 65 61 72 63 68 20 54 6f 6f 6c 62 61 72 5c } //1 WebSearch Toolbar\
		$a_01_2 = {43 4c 53 49 44 5c 7b 00 ff ff ff ff 01 00 00 00 2d 00 00 00 ff ff ff ff 06 00 00 00 2d 42 32 33 44 2d 00 00 ff ff ff ff 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_WinTools_3{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {57 65 62 53 65 61 72 63 68 20 45 61 73 79 20 49 6e 73 74 61 6c 6c 65 72 } //1 WebSearch Easy Installer
		$a_01_2 = {57 69 6e 54 6f 6f 6c 73 5c } //1 WinTools\
		$a_01_3 = {77 74 6f 6f 6c 73 61 2e 65 78 65 } //1 wtoolsa.exe
		$a_01_4 = {43 4c 53 49 44 5c 7b 38 37 30 36 37 46 30 34 2d 44 45 34 43 2d 34 36 38 38 2d 42 43 33 43 2d 34 46 43 46 33 39 44 36 30 39 45 37 7d } //1 CLSID\{87067F04-DE4C-4688-BC3C-4FCF39D609E7}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_WinTools_4{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 69 64 20 79 6f 75 20 6b 6e 6f 77 20 61 6c 6c 20 74 68 65 20 61 64 76 61 6e 74 61 67 65 73 20 6f 66 20 74 68 65 20 57 65 62 53 65 61 72 63 68 20 54 6f 6f 6c 62 61 72 3f } //1 Did you know all the advantages of the WebSearch Toolbar?
		$a_01_1 = {57 41 52 4e 49 4e 47 21 20 59 6f 75 20 6d 61 79 20 68 61 76 65 20 53 70 79 77 61 72 65 20 6f 6e 20 79 6f 75 72 20 50 43 20 77 69 74 68 6f 75 74 20 79 6f 75 72 20 6b 6e 6f 77 6c 65 64 67 65 21 } //1 WARNING! You may have Spyware on your PC without your knowledge!
		$a_01_2 = {54 42 50 53 2e 65 78 65 20 2f 69 6e 73 74 61 6c 6c 73 6b 69 6e } //1 TBPS.exe /installskin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_WinTools_5{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {78 72 32 79 77 72 78 37 } //5 xr2ywrx7
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 54 6f 6f 6c 73 5c 6b 79 64 6d 7a 79 6c 6b 69 } //5 Software\WinTools\kydmzylki
		$a_01_3 = {57 54 6f 6f 6c 73 41 2e 65 78 65 } //1 WToolsA.exe
		$a_01_4 = {57 54 6f 6f 6c 73 42 2e 64 6c 6c } //1 WToolsB.dll
		$a_01_5 = {57 54 6f 6f 6c 73 43 2e 63 66 67 } //1 WToolsC.cfg
		$a_01_6 = {57 54 6f 6f 6c 73 50 2e 63 66 67 } //1 WToolsP.cfg
		$a_01_7 = {57 54 6f 6f 6c 73 44 2e 63 66 67 } //1 WToolsD.cfg
		$a_03_8 = {41 5f 53 5f 56 5f 32 ?? 43 6c 6f 73 65 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1) >=16
 
}
rule Trojan_Win32_WinTools_6{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,24 00 20 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {57 69 6e 2d 54 6f 6f 6c 73 20 45 61 73 79 20 49 6e 73 74 61 6c 6c 65 72 20 55 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 50 72 6f 67 72 65 73 73 } //10 Win-Tools Easy Installer Uninstallation Progress
		$a_01_2 = {44 69 64 20 79 6f 75 20 6b 6e 6f 77 20 61 6c 6c 20 74 68 65 20 61 64 76 61 6e 74 61 67 65 73 20 74 68 65 20 57 69 6e 54 6f 6f 6c 73 3f } //10 Did you know all the advantages the WinTools?
		$a_01_3 = {57 54 6f 6f 6c 73 42 2e 64 6c 6c } //2 WToolsB.dll
		$a_01_4 = {57 54 6f 6f 6c 73 41 2e 65 78 65 } //2 WToolsA.exe
		$a_01_5 = {25 63 5f 68 69 73 74 25 } //1 %c_hist%
		$a_01_6 = {3c 2f 73 68 6f 77 5f 61 64 3e } //1 </show_ad>
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=32
 
}
rule Trojan_Win32_WinTools_7{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {57 54 6f 6f 6c 73 41 2e 65 78 65 } //10 WToolsA.exe
		$a_01_2 = {57 54 6f 6f 6c 73 42 2e 64 6c 6c } //10 WToolsB.dll
		$a_01_3 = {57 54 6f 6f 6c 73 43 2e 63 66 67 } //2 WToolsC.cfg
		$a_01_4 = {57 54 6f 6f 6c 73 50 2e 63 66 67 } //2 WToolsP.cfg
		$a_01_5 = {57 54 6f 6f 6c 73 44 2e 63 66 67 } //2 WToolsD.cfg
		$a_01_6 = {57 54 6f 6f 6c 73 53 2e 65 78 65 } //2 WToolsS.exe
		$a_01_7 = {43 6f 6d 6d 6f 6e 20 66 69 6c 65 73 5c 57 69 6e 54 6f 6f 6c 73 } //2 Common files\WinTools
		$a_01_8 = {41 64 53 75 70 70 6f 72 74 55 6e 62 72 65 61 6b } //1 AdSupportUnbreak
		$a_01_9 = {3c 2f 73 68 6f 77 5f 61 64 3e } //1 </show_ad>
		$a_01_10 = {25 63 5f 68 69 73 74 25 } //1 %c_hist%
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=41
 
}
rule Trojan_Win32_WinTools_8{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {57 65 62 53 65 61 72 63 68 20 44 6f 77 6e 6c 6f 61 64 65 72 } //1 WebSearch Downloader
		$a_01_2 = {57 65 62 53 65 61 72 63 68 20 54 6f 6f 6c 62 61 72 20 55 70 64 61 74 65 } //1 WebSearch Toolbar Update
		$a_01_3 = {54 68 65 20 74 6f 6f 6c 62 61 72 20 68 61 73 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 75 70 64 61 74 65 64 21 } //1 The toolbar has been successfully updated!
		$a_01_4 = {57 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 72 65 73 74 61 72 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 74 6f 20 6d 61 6b 65 20 74 68 65 20 63 68 61 6e 67 65 20 74 61 6b 65 20 65 66 66 65 63 74 3f } //1 Would you like restart your computer to make the change take effect?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_WinTools_9{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 19 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //15 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {41 53 5f 56 5f 32 5f 48 6f 6f 6b 5f 4d 61 70 } //5 AS_V_2_Hook_Map
		$a_01_2 = {41 53 56 32 5f 48 6f 6f 6b 4d 74 78 } //5 ASV2_HookMtx
		$a_01_3 = {41 5f 53 5f 56 5f 32 5f 4d 74 78 } //5 A_S_V_2_Mtx
		$a_01_4 = {41 5f 53 5f 56 5f 32 5f 43 6c 6f 73 65 } //3 A_S_V_2_Close
		$a_01_5 = {53 54 5f 56 5f 33 5f 48 6f 6f 6b 5f 4d 61 70 } //3 ST_V_3_Hook_Map
		$a_01_6 = {77 65 62 73 65 61 72 63 68 2e 63 6f 6d } //3 websearch.com
		$a_01_7 = {61 64 77 61 76 65 2e 63 6f 6d } //3 adwave.com
		$a_01_8 = {57 54 6f 6f 6c 73 41 2e 65 78 65 } //2 WToolsA.exe
		$a_01_9 = {57 54 6f 6f 6c 73 42 2e 64 6c 6c } //2 WToolsB.dll
		$a_01_10 = {57 53 75 70 2e 65 78 65 } //2 WSup.exe
		$a_01_11 = {41 64 53 57 6e 64 50 72 6f 63 } //1 AdSWndProc
		$a_01_12 = {41 64 53 75 70 70 6f 72 74 55 6e 62 72 65 61 6b } //1 AdSupportUnbreak
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=25
 
}
rule Trojan_Win32_WinTools_10{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2c 39 39 20 42 6f 72 6c 61 6e 64 } //1 Portions Copyright (c) 1983,99 Borland
		$a_01_1 = {57 69 6e 54 6f 6f 6c 73 5c 77 74 6f 6f 6c 73 61 2e 65 78 65 } //1 WinTools\wtoolsa.exe
		$a_01_2 = {43 4c 53 49 44 5c 7b 38 37 30 36 37 46 30 34 2d 44 45 34 43 2d 34 36 38 38 2d 42 43 33 43 2d 34 46 43 46 33 39 44 36 30 39 45 37 7d } //1 CLSID\{87067F04-DE4C-4688-BC3C-4FCF39D609E7}
		$a_03_3 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 44 6e 6c 2f 54 5f ?? ?? ?? ?? ?? 2f 57 69 6e 54 6f 6f 6c 73 2e 63 61 62 } //1
		$a_03_4 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 54 62 [0-04] 49 6e 73 74 4c 6f 67 2e 61 73 6d 78 2f 47 65 74 58 4d 4c 3f 54 62 49 64 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule Trojan_Win32_WinTools_11{
	meta:
		description = "Trojan:Win32/WinTools,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1d 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //20 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {44 4f 57 4e 4c 4f 41 44 3d 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 64 6e 6c 2f 54 } //4 DOWNLOAD=http://download.websearch.com/dnl/T
		$a_00_2 = {43 4c 53 49 44 5c 7b 33 33 39 42 42 32 33 46 2d 41 38 36 34 2d 34 38 43 30 2d 41 35 39 46 2d 32 39 45 41 39 31 35 39 36 35 45 43 7d 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //4 CLSID\{339BB23F-A864-48C0-A59F-29EA915965EC}\InProcServer32
		$a_01_3 = {53 65 61 72 63 68 20 54 6f 6f 6c 62 61 72 20 32 2e 30 20 66 72 6f 6d 20 57 65 62 20 53 65 61 72 63 68 } //3 Search Toolbar 2.0 from Web Search
		$a_00_4 = {77 69 6e 2d 74 6f 6f 6c 73 2e 63 6f 6d 2f 66 61 71 5f 73 74 2e 61 73 70 78 } //1 win-tools.com/faq_st.aspx
		$a_00_5 = {77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 6c 65 67 61 6c } //1 websearch.com/legal
		$a_01_6 = {57 49 4e 54 4f 4f 4c 53 20 45 4e 44 2d 55 53 45 52 20 4c 49 43 45 4e 53 45 } //1 WINTOOLS END-USER LICENSE
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*4+(#a_00_2  & 1)*4+(#a_01_3  & 1)*3+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=29
 
}