
rule BrowserModifier_Win32_Prifou{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 63 46 6f 75 6e 74 61 69 6e } //1 PrcFountain
		$a_01_1 = {50 72 69 63 65 20 46 6f 75 6e 74 61 69 6e } //1 Price Fountain
		$a_01_2 = {66 78 61 63 78 71 36 38 0d 6f 71 71 00 } //1
		$a_01_3 = {59 61 78 72 70 78 57 6a 71 78 46 00 } //1 慙牸硰橗硱F
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_2{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {45 49 6e 76 61 6c 69 64 4f 70 65 72 61 74 69 6f 6e } //1 EInvalidOperation
		$a_00_1 = {76 69 72 74 75 61 6c 61 6c 6c 6f 63 } //1 virtualalloc
		$a_00_2 = {56 69 72 74 75 61 6c 46 72 65 65 } //1 VirtualFree
		$a_02_3 = {8b 45 fc 80 b8 ?? 00 00 00 00 74 ec } //1
		$a_02_4 = {ff ff 84 c0 74 ?? e8 ?? ?? 00 00 68 } //1
		$a_03_5 = {ff ff 5d c2 10 00 90 09 0a 00 a1 ?? ?? ?? 00 8b 00 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}
rule BrowserModifier_Win32_Prifou_3{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 8b 06 0f b6 44 18 ff 89 45 f4 8b c6 e8 ?? ?? ?? ?? 8b 55 f8 8b 4d f4 8a 14 0a 88 54 18 ff 43 4f 75 de 33 c0 5a 59 59 } //1
		$a_01_1 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } //1 \UpdateProc\UpdateTask.exe
		$a_01_2 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 61 00 74 00 } //1 \UpdateProc\config.dat
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule BrowserModifier_Win32_Prifou_4{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 } //1 SOFTWARE\PriceMeter
		$a_01_1 = {70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 77 00 2e 00 65 00 78 00 65 00 } //1 pricemeterw.exe
		$a_01_2 = {5f 00 5f 00 70 00 6d 00 4c 00 6f 00 67 00 5f 00 2e 00 74 00 78 00 74 00 } //1 __pmLog_.txt
		$a_01_3 = {63 65 66 5f 62 69 6e 61 72 79 5f 64 65 61 6c 70 6c 79 } //1 cef_binary_dealply
		$a_01_4 = {43 68 69 63 6b 65 6e 41 70 70 2e 6f 70 65 6e 55 52 4c 20 3d 20 66 75 6e 63 74 69 6f 6e 28 75 72 6c 29 } //1 ChickenApp.openURL = function(url)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule BrowserModifier_Win32_Prifou_5{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 69 00 63 00 65 00 20 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 } //1 Price Fountain
		$a_01_1 = {6b 00 69 00 70 00 69 00 32 00 2e 00 73 00 74 00 6f 00 72 00 65 00 70 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 64 00 65 00 78 00 36 00 2e 00 70 00 68 00 70 00 } //1 kipi2.storepm.com/index6.php
		$a_01_2 = {74 00 79 00 70 00 65 00 3d 00 6f 00 66 00 66 00 62 00 26 00 74 00 6f 00 70 00 69 00 63 00 3d 00 75 00 72 00 6c 00 64 00 61 00 74 00 26 00 64 00 61 00 74 00 61 00 3d 00 31 00 } //1 type=offb&topic=urldat&data=1
		$a_01_3 = {53 75 7a 61 6e 44 4c 4c 5c 52 65 6c 65 61 73 65 5c 73 75 7a 61 6e 77 2e 70 64 62 } //1 SuzanDLL\Release\suzanw.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_6{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 43 53 63 72 69 70 74 2e 65 78 65 22 20 20 2f 2f 62 20 2f 2f 65 3a 76 62 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f } //1 \CScript.exe"  //b //e:vbscript //nologo
		$a_01_1 = {68 74 74 70 3a 2f 2f 69 6e 73 2e 70 72 69 63 65 6a 73 2e 6e 65 74 2f 64 65 61 6c 64 6f 2f 69 6e 73 74 61 6c 6c 2d 72 65 70 6f 72 74 3f 74 79 70 65 3d 69 6e 73 74 61 6c 6c } //1 http://ins.pricejs.net/dealdo/install-report?type=install
		$a_01_2 = {26 69 6e 73 74 67 72 70 3d } //1 &instgrp=
		$a_01_3 = {64 6c 6c 2d 66 69 6c 65 2d 6e 61 6d 65 } //1 dll-file-name
		$a_01_4 = {5c 52 6b 65 79 2e 64 61 74 } //1 \Rkey.dat
		$a_01_5 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 42 6f 6f 6b 69 6e 67 20 2e 6c 6e 6b } //1 \Start Menu\Programs\Booking .lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule BrowserModifier_Win32_Prifou_7{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 } //1 SOFTWARE\PriceMeter
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 4f 00 70 00 74 00 6f 00 75 00 74 00 } //1 SOFTWARE\BrowserOptout
		$a_01_2 = {70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 77 00 2e 00 65 00 78 00 65 00 } //1 pricemeterw.exe
		$a_01_3 = {74 00 79 00 70 00 65 00 3d 00 6f 00 66 00 66 00 69 00 6e 00 73 00 74 00 26 00 74 00 6f 00 70 00 69 00 63 00 3d 00 64 00 6f 00 77 00 6e 00 73 00 74 00 61 00 72 00 74 00 } //1 type=offinst&topic=downstart
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_8{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 5c 00 70 00 72 00 69 00 63 00 65 00 66 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 PriceFountain\pricefountain.exe
		$a_01_1 = {50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 5f 00 44 00 4c 00 4c 00 } //1 PriceFountain_DLL
		$a_01_2 = {44 00 65 00 62 00 62 00 69 00 65 00 5f 00 } //1 Debbie_
		$a_03_3 = {3c 73 63 72 69 70 74 20 73 72 63 3d 27 68 74 74 70 3a 2f 2f 6a 2e 70 72 69 63 65 6a 73 2e 6e 65 74 2f [0-07] 2f 63 6f 6d 6d 6f 6e 2e 6a 73 3f 63 68 61 6e 6e 65 6c 3d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_9{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 } //1 Software\PriceFountain
		$a_01_1 = {28 00 65 00 50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 53 00 63 00 72 00 69 00 70 00 74 00 4f 00 62 00 6a 00 29 00 } //1 (ePriceFountainScriptObj)
		$a_01_2 = {43 00 4c 00 53 00 49 00 44 00 5c 00 7b 00 62 00 36 00 30 00 38 00 63 00 63 00 39 00 38 00 2d 00 35 00 34 00 64 00 65 00 2d 00 34 00 37 00 37 00 35 00 2d 00 39 00 36 00 63 00 39 00 2d 00 30 00 39 00 37 00 64 00 65 00 33 00 39 00 38 00 35 00 30 00 30 00 63 00 7d 00 } //1 CLSID\{b608cc98-54de-4775-96c9-097de398500c}
		$a_01_3 = {69 00 6e 00 73 00 74 00 67 00 72 00 70 00 } //1 instgrp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_10{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 } //1 SOFTWARE\PriceMeter
		$a_01_1 = {70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 77 00 2e 00 65 00 78 00 65 00 } //1 pricemeterw.exe
		$a_01_2 = {74 00 79 00 70 00 65 00 3d 00 6f 00 66 00 66 00 69 00 6e 00 73 00 74 00 26 00 74 00 6f 00 70 00 69 00 63 00 3d 00 77 00 64 00 72 00 75 00 6e 00 } //1 type=offinst&topic=wdrun
		$a_01_3 = {74 00 79 00 70 00 65 00 3d 00 6f 00 66 00 66 00 69 00 6e 00 73 00 74 00 26 00 74 00 6f 00 70 00 69 00 63 00 3d 00 70 00 6d 00 32 00 6b 00 72 00 79 00 32 00 } //1 type=offinst&topic=pm2kry2
		$a_01_4 = {57 61 74 63 68 44 6f 67 5c 52 65 6c 65 61 73 65 5c 70 72 69 63 65 6d 65 74 65 72 77 2e 70 64 62 } //1 WatchDog\Release\pricemeterw.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_11{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 } //1 Software\PriceMeterExpress
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 } //1 http://www.pricemeter.net/
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 72 00 61 00 69 00 6c 00 2e 00 66 00 69 00 6c 00 65 00 73 00 70 00 6d 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 65 00 61 00 6c 00 64 00 6f 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 72 00 65 00 70 00 6f 00 72 00 74 00 } //1 http://trail.filespm.com/dealdo/install-report
		$a_01_3 = {44 65 61 6c 50 6c 79 5c 44 65 61 6c 50 6c 79 53 65 74 75 70 } //1 DealPly\DealPlySetup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_12{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 43 53 63 72 69 70 74 2e 65 78 65 22 20 20 2f 2f 62 20 2f 2f 65 3a 76 62 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f } //1 \CScript.exe"  //b //e:vbscript //nologo
		$a_01_1 = {5c 55 6e 69 6e 73 74 61 6c 6c 5c 50 72 69 63 65 46 6f 75 6e 74 61 69 6e } //1 \Uninstall\PriceFountain
		$a_01_2 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 50 72 69 63 65 46 6f 75 6e 74 61 69 6e 00 } //1 楄灳慬乹浡e牐捩䙥畯瑮楡n
		$a_01_3 = {50 46 20 49 6e 73 74 61 6c 6c 65 72 } //1 PF Installer
		$a_01_4 = {68 74 74 70 3a 2f 2f 69 6e 73 2e 70 72 69 63 65 6a 73 2e 6e 65 74 2f 64 65 61 6c 64 6f 2f 69 6e 73 74 61 6c 6c 2d 72 65 70 6f 72 74 3f 74 79 70 65 3d 69 6e 73 74 61 6c 6c } //1 http://ins.pricejs.net/dealdo/install-report?type=install
		$a_03_5 = {2f 69 6e 73 74 61 6c 6c 20 2f 55 6e 4e 6d 3d 22 55 70 64 61 74 65 90 0e 05 00 66 6f 72 90 0e 05 00 50 72 69 63 65 46 6f 75 6e 74 61 69 6e 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_13{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 00 70 00 69 00 5c 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 5c 00 70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 2e 00 78 00 75 00 6c 00 } //1 xpi\content\pricemeterexpress.xul
		$a_01_1 = {66 00 69 00 6c 00 65 00 73 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 2e 00 63 00 72 00 78 00 } //1 files\PriceMeterExpress.crx
		$a_01_2 = {66 00 69 00 6c 00 65 00 73 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 2e 00 78 00 70 00 69 00 } //1 files\PriceMeterExpress.xpi
		$a_01_3 = {66 00 69 00 6c 00 65 00 73 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 49 00 45 00 2e 00 64 00 6c 00 6c 00 } //1 files\PriceMeterExpressIE.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_14{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 } //1 Software\PriceMeter
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 44 00 65 00 61 00 6c 00 50 00 6c 00 79 00 4c 00 69 00 76 00 65 00 } //1 Software\DealPlyLive
		$a_01_2 = {24 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2d 00 69 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 2d 00 69 00 65 00 } //1 $browser-identifier-ie
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 67 00 6f 00 2f 00 70 00 6f 00 73 00 74 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 26 00 70 00 61 00 72 00 74 00 6e 00 65 00 72 00 3d 00 } //1 http://www.pricemeter.net/go/postinstall/?action=install&partner=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule BrowserModifier_Win32_Prifou_15{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 } //1 Software\PriceFountain
		$a_01_1 = {73 00 75 00 7a 00 61 00 6e 00 5f 00 77 00 64 00 72 00 75 00 6e 00 } //1 suzan_wdrun
		$a_01_2 = {73 00 75 00 7a 00 61 00 6e 00 5f 00 77 00 64 00 64 00 6f 00 77 00 6f 00 } //1 suzan_wddowo
		$a_01_3 = {73 00 75 00 7a 00 61 00 6e 00 5f 00 77 00 64 00 6e 00 6f 00 74 00 72 00 75 00 6e 00 } //1 suzan_wdnotrun
		$a_01_4 = {5c 00 6c 00 6f 00 67 00 73 00 5c 00 77 00 64 00 2e 00 6c 00 6f 00 67 00 } //1 \logs\wd.log
		$a_01_5 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 75 00 6d 00 70 00 73 00 74 00 65 00 72 00 2d 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 68 00 65 00 72 00 6f 00 6b 00 75 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2f 00 71 00 75 00 65 00 72 00 79 00 } //1 https://dumpster-server.herokuapp.com/manager/query
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule BrowserModifier_Win32_Prifou_16{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 6c 65 61 73 65 2e 64 6c 6c 00 52 75 6e 00 } //20
		$a_01_1 = {58 59 5a 50 68 52 75 6e 00 54 52 51 e8 04 00 00 00 ff d0 83 c4 04 c3 } //20
		$a_01_2 = {5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 5c 00 42 00 52 00 41 00 4e 00 44 00 5f 00 4e 00 41 00 4d 00 45 00 22 00 2c 00 22 00 57 00 53 00 43 00 52 00 49 00 50 00 54 00 5f 00 43 00 4d 00 44 00 5f 00 4e 00 41 00 4d 00 45 00 20 00 2f 00 45 00 3a 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 2f 00 42 00 20 00 22 00 22 00 22 00 20 00 26 00 20 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 75 00 6c 00 6c 00 4e 00 61 00 6d 00 65 00 } //1 \RunOnce\BRAND_NAME","WSCRIPT_CMD_NAME /E:vbscript /B """ & WScript.ScriptFullName
		$a_01_3 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 5c 00 55 00 70 00 64 00 61 00 74 00 65 00 54 00 61 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } //1 \UpdateProc\UpdateTask.exe
		$a_01_4 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 50 00 72 00 6f 00 63 00 5c 00 62 00 6b 00 75 00 70 00 2e 00 64 00 61 00 74 00 } //1 \UpdateProc\bkup.dat
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=42
 
}
rule BrowserModifier_Win32_Prifou_17{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 00 4d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 43 00 6c 00 73 00 2e 00 69 00 6e 00 6a 00 65 00 63 00 74 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 72 00 6f 00 6d 00 55 00 72 00 6c 00 28 00 75 00 72 00 6c 00 29 00 3b 00 } //1 PMExpressCls.injectScriptFromUrl(url);
		$a_01_1 = {44 00 65 00 61 00 6c 00 50 00 6c 00 79 00 43 00 6f 00 6e 00 66 00 69 00 67 00 4c 00 6f 00 63 00 61 00 6c 00 43 00 6c 00 73 00 2e 00 70 00 72 00 6f 00 74 00 6f 00 74 00 79 00 70 00 65 00 2e 00 67 00 65 00 74 00 50 00 61 00 72 00 74 00 6e 00 65 00 72 00 } //1 DealPlyConfigLocalCls.prototype.getPartner
		$a_01_2 = {26 00 61 00 70 00 70 00 54 00 69 00 74 00 6c 00 65 00 3d 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 2b 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 } //1 &appTitle=PriceMeter+Express
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 72 00 69 00 63 00 65 00 6d 00 65 00 74 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 } //1 http://www.pricemeter.net/
		$a_01_4 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 72 00 69 00 63 00 65 00 4d 00 65 00 74 00 65 00 72 00 } //1 SOFTWARE\PriceMeter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule BrowserModifier_Win32_Prifou_18{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,5c 00 5c 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 } //30 SOFTWARE\PriceFountain
		$a_01_1 = {70 00 72 00 69 00 63 00 65 00 6a 00 73 00 2e 00 6e 00 65 00 74 00 } //30 pricejs.net
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 75 00 6d 00 70 00 73 00 74 00 65 00 72 00 2d 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 68 00 65 00 72 00 6f 00 6b 00 75 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2f 00 71 00 75 00 65 00 72 00 79 00 } //30 https://dumpster-server.herokuapp.com/manager/query
		$a_01_3 = {73 00 75 00 7a 00 61 00 6e 00 5f 00 75 00 72 00 6c 00 5f 00 69 00 6e 00 6a 00 } //1 suzan_url_inj
		$a_01_4 = {73 00 75 00 7a 00 61 00 6e 00 5f 00 62 00 65 00 66 00 6f 00 72 00 65 00 64 00 6c 00 6c 00 69 00 6e 00 6a 00 } //1 suzan_beforedllinj
		$a_01_5 = {73 00 75 00 7a 00 61 00 6e 00 5f 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 5f 00 69 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 } //1 suzan_already_injected
		$a_01_6 = {73 00 75 00 7a 00 61 00 6e 00 64 00 6c 00 6c 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 70 00 61 00 74 00 68 00 } //1 suzandll_file_path
		$a_01_7 = {73 00 75 00 7a 00 61 00 6e 00 64 00 6c 00 6c 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 6e 00 61 00 6d 00 65 00 } //1 suzandll_file_name
		$a_01_8 = {53 75 7a 61 6e 45 58 45 2e 70 64 62 } //1 SuzanEXE.pdb
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*30+(#a_01_2  & 1)*30+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=92
 
}
rule BrowserModifier_Win32_Prifou_19{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 } //1 Software\PriceFountain
		$a_01_1 = {50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 49 00 45 00 2e 00 64 00 6c 00 6c 00 } //1 PriceFountainIE.dll
		$a_01_2 = {70 00 72 00 69 00 63 00 65 00 66 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 pricefountain.exe
		$a_01_3 = {24 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2d 00 69 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 2d 00 69 00 65 00 } //1 $browser-identifier-ie
		$a_01_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 73 00 2e 00 70 00 72 00 69 00 63 00 65 00 6a 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 64 00 65 00 61 00 6c 00 64 00 6f 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 72 00 65 00 70 00 6f 00 72 00 74 00 } //1 http://ins.pricejs.net/dealdo/install-report
		$a_01_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 50 00 72 00 69 00 63 00 65 00 46 00 6f 00 75 00 6e 00 74 00 61 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 2f 00 67 00 6f 00 2f 00 70 00 6f 00 73 00 74 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 26 00 70 00 61 00 72 00 74 00 6e 00 65 00 72 00 3d 00 } //1 http://www.PriceFountain.net/go/postinstall/?action=install&partner=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}