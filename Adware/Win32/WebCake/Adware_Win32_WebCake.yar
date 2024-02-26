
rule Adware_Win32_WebCake{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 43 61 6b 65 44 65 73 6b 74 6f 70 } //01 00  WebCakeDesktop
		$a_01_1 = {59 32 44 65 73 6b 74 6f 70 2e 50 6c 75 67 49 6e 4f 53 } //01 00  Y2Desktop.PlugInOS
		$a_01_2 = {62 61 6b 65 20 63 61 6b 65 } //01 00  bake cake
		$a_01_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 4f 00 53 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_WebCake_2{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 43 61 6b 65 44 65 73 6b 74 6f 70 } //01 00  WebCakeDesktop
		$a_01_1 = {57 65 62 43 61 6b 65 20 4c 4c 43 2e 20 41 6c 6c 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2e } //01 00  WebCake LLC. All rights reserved.
		$a_01_2 = {57 65 62 43 61 6b 65 2e 44 65 73 6b 74 6f 70 } //01 00  WebCake.Desktop
		$a_01_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 57 00 65 00 62 00 43 00 61 00 6b 00 65 00 } //00 00 
		$a_00_4 = {78 } //a4 00  x
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_WebCake_3{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 70 6c 75 67 69 6e 5f 67 65 74 77 65 62 63 61 6b 65 5f 63 6f 6d } //01 00  get_plugin_getwebcake_com
		$a_01_1 = {75 00 73 00 65 00 72 00 5f 00 70 00 72 00 65 00 66 00 28 00 22 00 65 00 78 00 74 00 65 00 6e 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 77 00 65 00 62 00 63 00 61 00 6b 00 65 00 2e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 49 00 64 00 22 00 } //01 00  user_pref("extentions.webcake.installId"
		$a_01_2 = {57 00 65 00 62 00 43 00 61 00 6b 00 65 00 2e 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 4f 00 53 00 } //00 00  WebCake.Desktop.OS
		$a_00_3 = {78 } //a8 00  x
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_WebCake_4{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 70 00 69 00 2e 00 67 00 65 00 74 00 77 00 65 00 62 00 63 00 61 00 6b 00 65 00 2e 00 63 00 6f 00 6d 00 } //01 00  api.getwebcake.com
		$a_01_1 = {57 65 62 43 61 6b 65 20 4c 61 79 65 72 73 20 41 70 69 } //01 00  WebCake Layers Api
		$a_00_2 = {50 72 6f 67 49 44 20 3d 20 73 20 27 57 65 62 43 61 6b 65 49 45 43 6c 69 65 6e 74 2e 4c 61 79 65 72 73 2e 31 27 0d 0a } //01 00 
		$a_03_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 57 00 65 00 62 00 90 05 02 02 00 20 43 00 61 00 6b 00 65 00 90 00 } //00 00 
		$a_00_4 = {78 } //b5 00  x
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_WebCake_5{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 65 00 62 00 43 00 61 00 6b 00 65 00 49 00 45 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //01 00  WebCakeIEClient
		$a_01_1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 32 00 30 00 31 00 33 00 20 00 4c 00 65 00 74 00 20 00 54 00 68 00 65 00 6d 00 20 00 45 00 61 00 74 00 20 00 57 00 65 00 62 00 2d 00 43 00 61 00 6b 00 65 00 20 00 4c 00 4c 00 43 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 } //00 00  Copyright (c) 2013 Let Them Eat Web-Cake LLC.  All rights reserved.
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_WebCake_6{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 53 55 20 4c 6f 61 64 65 72 00 } //01 00 
		$a_03_1 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 63 00 29 00 20 00 32 00 30 00 31 00 33 00 20 00 57 00 65 00 62 00 90 02 02 43 00 61 00 6b 00 65 00 20 00 4c 00 4c 00 43 00 2e 00 20 00 20 00 41 00 6c 00 6c 00 20 00 72 00 69 00 67 00 68 00 74 00 73 00 20 00 72 00 65 00 73 00 65 00 72 00 76 00 65 00 64 00 2e 00 90 00 } //01 00 
		$a_03_2 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 57 00 65 00 62 00 90 05 02 02 00 20 43 00 61 00 6b 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_WebCake_7{
	meta:
		description = "Adware:Win32/WebCake,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 72 00 6f 00 77 00 73 00 65 00 72 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 2e 00 64 00 6c 00 6c 00 } //01 00  BrowserProtect.dll
		$a_01_1 = {66 6a 6f 69 6a 64 61 6e 68 61 69 66 6c 68 69 62 6b 6c 6a 65 6b 6c 63 67 68 63 6d 6d 66 66 66 68 } //01 00  fjoijdanhaiflhibkljeklcghcmmfffh
		$a_01_2 = {75 72 6c 73 5f 74 6f 5f 72 65 73 74 6f 72 65 5f 6f 6e 5f 73 74 61 72 74 75 70 22 3a 20 5b 20 22 68 74 74 70 3a 2f 2f 73 65 61 72 63 68 2e 67 65 74 77 65 62 63 61 6b 65 2e 63 6f 6d 2f 22 20 5d 7d } //01 00  urls_to_restore_on_startup": [ "http://search.getwebcake.com/" ]}
		$a_01_3 = {57 65 62 43 61 6b 65 20 4c 6f 75 64 20 49 6e 73 74 61 6c 6c 65 72 20 28 4d 61 69 6e 29 5c 42 69 6e 61 72 69 65 73 5c 57 65 62 43 61 6b 65 43 68 72 6f 6d 65 57 61 74 63 68 2e 70 64 62 } //00 00  WebCake Loud Installer (Main)\Binaries\WebCakeChromeWatch.pdb
		$a_00_4 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}