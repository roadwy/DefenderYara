
rule Adware_Win32_Hotbar{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {76 69 63 70 61 72 61 6d 65 74 65 72 73 } //01 00  vicparameters
		$a_00_1 = {64 65 66 62 72 6f 77 73 65 72 3d } //01 00  defbrowser=
		$a_01_2 = {8b 4e 1c 8b 56 10 53 53 51 52 53 ff d0 3b c3 7d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_2{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 5c 53 6f 75 72 63 65 5c 31 38 30 53 41 2e 63 70 70 } //01 00  .\Source\180SA.cpp
		$a_01_1 = {31 38 30 73 61 7c 31 38 30 61 64 73 6f 6c 75 74 69 6f 6e } //01 00  180sa|180adsolution
		$a_01_2 = {2f 73 68 6f 77 5f 61 64 73 3d } //00 00  /show_ads=
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_3{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 62 48 6f 73 74 49 45 2e 44 4c 4c 00 } //01 00 
		$a_01_1 = {65 63 68 6f 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f 73 6d 61 72 74 6f 66 66 65 72 73 } //01 00  echo.hotbar.com/smartoffers
		$a_01_2 = {55 70 67 72 61 64 65 53 6b 69 6e 53 79 73 74 65 6d } //00 00  UpgradeSkinSystem
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_4{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_01_1 = {26 62 6e 61 6d 65 3d 26 62 76 65 72 3d 26 76 65 72 3d 26 6d 74 3d 30 30 55 4e 4b 4e 4f 57 4e } //01 00  &bname=&bver=&ver=&mt=00UNKNOWN
		$a_01_2 = {7c 63 73 63 69 64 7c 68 64 69 64 7c 6d 74 } //00 00  |cscid|hdid|mt
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_5{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 62 48 6f 73 74 4f 45 2e 44 4c 4c 00 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 5c 48 6f 74 62 61 72 5c 00 49 6e 73 74 61 6c 6c 00 48 6f 74 62 61 72 } //01 00  潓瑦慷敲䡜瑯慢屲潈扴牡\湉瑳污l潈扴牡
		$a_01_2 = {52 65 67 69 73 74 65 72 52 65 62 61 72 00 } //00 00  敒楧瑳牥敒慢r
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_6{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6f 74 62 61 72 53 41 48 6f 6f 6b 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {73 65 65 6b 6d 6f 73 61 7c 7a 61 6e 67 6f 73 61 7c 73 62 75 73 61 7c 68 6f 74 62 61 72 73 61 } //01 00  seekmosa|zangosa|sbusa|hotbarsa
		$a_01_2 = {25 73 20 53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //00 00  %s Search Assistant
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_7{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 8b 74 24 08 8b 0e 8b 01 8b 50 10 57 ff d2 83 7e 0c 00 8d 4e 0c 7c 90 01 01 3b 06 75 90 01 01 8b fe b8 01 00 00 00 f0 0f c1 01 90 00 } //01 00 
		$a_00_1 = {69 74 73 2e 6e 6f 74 2e 6f 6b } //01 00  its.not.ok
		$a_00_2 = {68 74 74 70 3a 2f 2f 6f 70 65 6e 2f 3f 75 72 6c 3d } //01 00  http://open/?url=
		$a_00_3 = {73 65 65 6b 6d 6f } //01 00  seekmo
		$a_00_4 = {68 6f 74 62 61 72 } //00 00  hotbar
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_8{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6c 6c 2e 73 65 63 75 72 65 77 65 62 73 69 74 65 61 63 63 65 73 73 2e 63 6f 6d } //01 00  install.securewebsiteaccess.com
		$a_01_1 = {69 6e 73 74 61 6c 6c 65 72 2f 7a 63 64 6f 77 6e 6c 6f 61 64 } //01 00  installer/zcdownload
		$a_01_2 = {63 72 61 7a 79 6c 6f 61 64 65 72 2e 63 6f 6d } //01 00  crazyloader.com
		$a_03_3 = {50 61 72 74 6e 65 72 90 01 05 43 72 61 7a 79 4c 6f 61 64 65 72 20 31 2e 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_9{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6f 77 6e 6c 6f 61 64 73 31 2e 7a 61 6e 67 6f 2e 63 6f 6d } //01 00  downloads1.zango.com
		$a_00_1 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 61 6e 63 65 6c 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 3f } //01 00  Are you sure you want to cancel the download?
		$a_03_2 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 90 01 01 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_10{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6c 6c 65 72 44 6f 6d 61 69 6e 3d 63 6f 6e 66 69 67 2e 68 6f 74 62 61 72 2e 63 6f 6d } //01 00  installerDomain=config.hotbar.com
		$a_01_1 = {73 65 6c 3d 68 62 6c 69 74 65 26 69 78 3d 50 50 4e 48 42 4c 69 74 65 } //01 00  sel=hblite&ix=PPNHBLite
		$a_01_2 = {48 6f 74 62 61 72 20 53 79 6e 64 69 63 61 74 69 6f 6e 20 50 6c 61 74 66 6f 72 6d 20 49 6e 73 74 61 6c 6c 65 72 } //01 00  Hotbar Syndication Platform Installer
		$a_01_3 = {48 6f 74 62 61 72 20 55 70 67 72 61 64 65 } //00 00  Hotbar Upgrade
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_11{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 5c 48 6f 74 62 61 72 5c 00 69 6e 73 74 61 6c 6c 00 48 6f 74 62 61 72 } //01 00  潓瑦慷敲䡜瑯慢屲潈扴牡\湩瑳污l潈扴牡
		$a_01_1 = {2e 68 6f 74 62 61 72 2e 63 6f 6d } //01 00  .hotbar.com
		$a_01_2 = {4e 48 62 48 6f 73 74 4f 45 50 61 74 68 } //01 00  NHbHostOEPath
		$a_01_3 = {43 48 62 43 6f 72 65 53 65 72 76 69 63 65 73 3a } //01 00  CHbCoreServices:
		$a_01_4 = {24 68 6f 74 62 61 72 62 69 6e 24 } //01 00  $hotbarbin$
		$a_01_5 = {48 62 48 6f 73 74 4f 45 2e 44 4c 4c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_12{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 65 72 69 66 79 53 69 67 6e 61 74 75 72 65 00 } //0a 00  敖楲祦楓湧瑡牵e
		$a_01_1 = {56 65 72 69 66 79 53 69 67 6e 61 74 75 72 65 4f 6e 50 61 72 65 6e 74 00 } //01 00  敖楲祦楓湧瑡牵佥偮牡湥t
		$a_01_2 = {50 69 6e 62 61 6c 6c 20 43 6f 72 70 6f 72 61 74 69 6f 6e 2e 00 } //01 00 
		$a_01_3 = {50 6c 61 74 72 69 75 6d 20 4c 4c 43 00 } //01 00 
		$a_01_4 = {5f 53 6d 61 72 74 53 68 6f 70 70 65 72 5f 42 75 69 6c 64 5f 53 6d 61 72 74 53 68 6f 70 70 65 72 5f } //00 00  _SmartShopper_Build_SmartShopper_
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_13{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {74 17 57 8b fa 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 5f 90 00 } //01 00 
		$a_01_1 = {2f 53 69 6c 65 6e 74 20 2f 57 65 6c 63 6f 6d 65 3d 66 61 6c 73 65 20 2f 41 66 66 69 6c 69 61 74 65 49 64 3d 24 } //01 00  /Silent /Welcome=false /AffiliateId=$
		$a_01_2 = {70 69 6e 62 61 6c 6c 70 75 62 6c 69 73 68 65 72 6e 65 74 77 6f 72 6b 2e 63 6f 6d 00 } //01 00 
		$a_01_3 = {69 63 73 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f 53 6f 66 74 77 61 72 65 2f } //00 00  ics.hotbar.com/Software/
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_14{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 08 00 08 00 00 03 00 "
		
	strings :
		$a_00_0 = {2e 57 65 53 6b 69 6e 2e 64 6c 6c } //05 00  .WeSkin.dll
		$a_00_1 = {77 65 61 74 68 65 72 2e 7a 61 6e 67 6f 2e 63 6f 6d 2f } //01 00  weather.zango.com/
		$a_00_2 = {72 61 64 61 72 2d 75 70 64 61 74 65 64 6f 6e } //01 00  radar-updatedon
		$a_00_3 = {52 41 44 41 52 53 4d 41 4c 4c } //01 00  RADARSMALL
		$a_00_4 = {52 41 44 41 52 42 49 47 } //01 00  RADARBIG
		$a_00_5 = {53 41 54 45 4c 4c 49 54 45 53 4d 41 4c 4c } //01 00  SATELLITESMALL
		$a_00_6 = {53 41 54 45 4c 4c 49 54 45 42 49 47 } //03 00  SATELLITEBIG
		$a_80_7 = {5a 61 6e 67 6f 2c 20 49 6e 63 2e } //Zango, Inc.  00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_15{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 65 62 75 67 53 65 74 74 69 6e 67 73 5f 50 6c 61 74 72 69 75 6d 00 } //01 00 
		$a_00_1 = {70 6c 61 74 72 69 75 6d 5f 68 6f 73 74 5f 66 69 6c 65 5f 65 64 69 74 00 } //01 00  汰瑡楲浵桟獯彴楦敬敟楤t
		$a_00_2 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 } //01 00  One8TSolutions
		$a_01_3 = {50 69 6e 62 61 6c 6c 20 43 6f 72 70 6f 72 61 74 69 6f 6e 2e 00 } //01 00 
		$a_01_4 = {76 65 72 3d 25 73 26 70 6b 67 5f 76 65 72 3d 25 73 26 65 70 61 72 61 6d 73 3d 73 } //01 00  ver=%s&pkg_ver=%s&eparams=s
		$a_01_5 = {61 64 5f 54 61 6b 65 66 6f 63 75 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_16{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6e 53 41 49 42 65 67 69 6e 49 6e 73 74 61 6c 6c 28 25 73 29 } //01 00  OnSAIBeginInstall(%s)
		$a_01_1 = {4e 6f 20 27 25 73 27 20 69 6e 20 56 49 43 20 72 65 73 70 6f 6e 73 65 } //01 00  No '%s' in VIC response
		$a_01_2 = {41 70 70 42 75 6e 64 6c 65 72 5f 52 53 41 5f 53 69 67 6e 65 72 } //01 00  AppBundler_RSA_Signer
		$a_01_3 = {56 49 43 20 55 52 4c 3a 20 25 73 } //01 00  VIC URL: %s
		$a_01_4 = {53 41 49 74 65 73 74 2e 74 78 74 } //01 00  SAItest.txt
		$a_01_5 = {41 56 43 41 53 41 49 41 70 70 40 61 70 70 65 6e 76 } //01 00  AVCASAIApp@appenv
		$a_01_6 = {53 00 41 00 49 00 45 00 63 00 68 00 6f 00 } //00 00  SAIEcho
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_17{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 63 6f 6d 70 69 6c 65 5c 73 6f 75 72 63 65 5f 74 62 5c 68 62 68 6f 73 74 69 65 5c } //01 00  \compile\source_tb\hbhostie\
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 5c } //01 00  Software\Hotbar\
		$a_00_2 = {24 68 6f 74 62 61 72 62 69 6e 24 } //01 00  $hotbarbin$
		$a_00_3 = {24 68 6f 74 62 61 72 24 } //01 00  $hotbar$
		$a_00_4 = {68 6f 74 62 61 72 5f 70 72 6f 6d 6f } //01 00  hotbar_promo
		$a_00_5 = {2d 48 6f 74 62 61 72 2d 68 62 72 2e } //01 00  -Hotbar-hbr.
		$a_80_6 = {48 6f 74 62 61 72 2e 63 6f 6d 2f } //Hotbar.com/  01 00 
		$a_00_7 = {47 65 74 48 6f 74 62 61 72 48 6f 6d 65 44 69 72 } //00 00  GetHotbarHomeDir
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_18{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {54 65 73 74 69 6e 67 20 66 6f 72 90 02 08 54 6f 6f 6c 62 61 72 90 00 } //01 00 
		$a_00_1 = {4d 61 74 63 68 65 64 20 73 61 } //01 00  Matched sa
		$a_00_2 = {64 69 64 3d 25 73 26 62 72 61 6e 64 69 64 3d 25 73 26 6f 73 3d 25 73 26 25 73 26 76 65 72 3d 25 73 26 70 6b 67 5f 76 65 72 3d 25 73 26 65 70 61 72 61 6d 73 3d 25 73 } //01 00  did=%s&brandid=%s&os=%s&%s&ver=%s&pkg_ver=%s&eparams=%s
		$a_00_3 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 } //01 00  One8TSolutions
		$a_00_4 = {5a 61 6e 67 6f 54 6f 6f 6c 62 61 72 } //01 00  ZangoToolbar
		$a_00_5 = {48 6f 74 62 61 72 54 6f 6f 6c 62 61 72 } //00 00  HotbarToolbar
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_19{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 31 45 45 32 35 33 32 2d 41 31 37 45 2d 31 31 44 45 2d 42 42 39 35 2d 37 43 42 37 35 35 44 38 39 35 39 33 } //01 00  91EE2532-A17E-11DE-BB95-7CB755D89593
		$a_01_1 = {70 69 6e 62 61 6c 6c 70 75 62 6c 69 73 68 65 72 6e 65 74 77 6f 72 6b 2e 63 6f 6d } //01 00  pinballpublishernetwork.com
		$a_01_2 = {48 74 54 70 3a 2f 2f 55 43 49 25 32 30 50 61 67 65 25 32 30 44 77 6e 6c 6f 61 64 } //01 00  HtTp://UCI%20Page%20Dwnload
		$a_01_3 = {53 6d 61 72 74 20 53 68 6f 70 70 65 72 20 49 6e 63 00 00 00 5a 61 6e 67 6f 00 00 00 42 6c 69 6e 6b 78 00 00 50 69 6e 62 61 6c 6c 20 43 6f 72 70 6f 72 61 74 69 6f 6e 2e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_20{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {54 65 73 74 69 6e 67 20 66 6f 72 20 48 42 90 02 04 4c 69 74 65 00 90 00 } //01 00 
		$a_00_1 = {63 6c 69 65 6e 74 61 78 70 72 6f 78 79 2e 64 6c 6c 00 } //01 00 
		$a_00_2 = {53 41 41 6c 69 61 73 3a 20 25 73 } //01 00  SAAlias: %s
		$a_00_3 = {53 41 25 73 3a 20 25 73 00 00 00 00 41 6c 69 61 73 } //01 00 
		$a_00_4 = {64 69 64 3d 25 73 26 62 72 61 6e 64 69 64 3d 25 73 26 6f 73 3d 25 73 26 25 73 26 76 65 72 3d 25 73 26 70 6b 67 5f 76 65 72 3d 25 73 26 65 70 61 72 61 6d 73 3d 25 73 } //01 00  did=%s&brandid=%s&os=%s&%s&ver=%s&pkg_ver=%s&eparams=%s
		$a_00_5 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 } //00 00  One8TSolutions
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_21{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 53 65 6e 64 69 6e 67 20 6e 65 77 20 55 52 4c 20 6d 65 73 73 61 67 65 20 74 6f 20 73 65 61 72 63 68 20 61 73 73 69 73 74 61 6e 74 20 77 69 6e 64 6f 77 28 30 78 25 30 38 58 29 } //01 00  HOOK_DLL: Sending new URL message to search assistant window(0x%08X)
		$a_02_1 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 48 69 64 65 20 41 90 02 08 77 69 6e 64 6f 77 20 28 30 78 25 78 29 90 00 } //01 00 
		$a_00_2 = {53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //01 00  Search Assistant
		$a_00_3 = {73 6f 66 74 77 61 72 65 5c 7a 61 6e 67 6f } //01 00  software\zango
		$a_00_4 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } //02 00  enable_ts_logging
		$a_00_5 = {4c 00 69 00 74 00 65 00 } //00 00  Lite
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_22{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {6e 70 63 6c 6e 74 61 78 5f 48 42 90 02 05 53 41 2e 64 6c 6c 90 00 } //01 00 
		$a_02_1 = {48 00 42 00 4c 00 69 00 74 00 65 00 90 02 02 41 00 58 00 2e 00 49 00 6e 00 90 02 02 66 00 6f 00 90 00 } //01 00 
		$a_00_2 = {48 00 6f 00 74 00 62 00 61 00 72 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 20 00 50 00 6c 00 75 00 67 00 69 00 6e 00 00 00 } //01 00 
		$a_00_3 = {6e 70 63 6c 6e 74 61 78 5f 48 6f 74 62 61 72 53 41 2e 64 6c 6c 00 } //0a 00  灮汣瑮硡䡟瑯慢卲⹁汤l
		$a_00_4 = {4e 50 5f 47 65 74 45 6e 74 72 79 50 6f 69 6e 74 73 00 4e 50 5f 49 6e 69 74 69 61 6c 69 7a 65 00 4e 50 5f 53 68 75 74 64 6f 77 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_23{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {48 42 4c 69 74 65 53 41 48 6f 6f 6b 2e 64 6c 6c } //01 00  HBLiteSAHook.dll
		$a_02_1 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 48 69 64 65 20 41 90 02 08 77 69 6e 64 6f 77 20 28 30 78 25 78 29 90 00 } //01 00 
		$a_00_2 = {49 45 4c 69 73 74 65 6e 65 72 20 74 72 69 65 64 20 74 6f 20 64 69 73 63 6f 6e 6e 65 63 74 2c 20 62 75 74 } //01 00  IEListener tried to disconnect, but
		$a_02_3 = {42 69 6c 6c 79 42 6f 62 90 02 08 20 77 69 6e 64 6f 77 20 63 6c 61 73 73 20 72 65 67 69 73 74 65 72 20 65 72 72 6f 72 3a 20 25 64 2e 90 00 } //01 00 
		$a_00_4 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 41 44 20 70 72 6f 63 65 73 73 20 49 44 20 28 30 78 25 30 38 58 29 20 65 71 75 61 6c 73 } //00 00  HOOK_DLL: AD process ID (0x%08X) equals
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_24{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 6f 70 65 6e 72 65 71 75 65 73 74 61 } //0a 00  httpopenrequesta
		$a_00_1 = {69 6e 74 65 72 6e 65 74 63 6f 6e 6e 65 63 74 61 } //0a 00  internetconnecta
		$a_01_2 = {48 00 42 00 49 00 6e 00 73 00 74 00 49 00 45 00 2e 00 48 00 62 00 49 00 6e 00 73 00 74 00 4f 00 62 00 6a 00 } //01 00  HBInstIE.HbInstObj
		$a_01_3 = {75 70 67 72 61 64 65 69 6e 66 6f 2e 76 65 72 } //01 00  upgradeinfo.ver
		$a_01_4 = {68 6f 74 62 61 72 5c 62 69 6e 5c } //01 00  hotbar\bin\
		$a_01_5 = {68 74 74 70 3a 2f 2f 69 6e 73 74 61 6c 6c 73 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f 69 6e 73 74 61 6c 6c 73 2f 68 6f 74 62 61 72 2f 70 72 6f 67 72 61 6d 73 2f } //01 00  http://installs.hotbar.com/installs/hotbar/programs/
		$a_01_6 = {48 6f 74 62 61 72 2e 65 78 65 } //01 00  Hotbar.exe
		$a_01_7 = {57 65 61 74 68 65 72 4f 6e 54 72 61 79 } //00 00  WeatherOnTray
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_25{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 00 6f 00 74 00 62 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 20 00 49 00 6e 00 63 00 2e 00 } //01 00  Hotbar.com Inc.
		$a_00_1 = {48 00 6f 00 74 00 62 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 2c 00 20 00 49 00 6e 00 63 00 2e 00 } //02 00  Hotbar.com, Inc.
		$a_00_2 = {3b 20 48 6f 74 62 61 72 } //02 00  ; Hotbar
		$a_00_3 = {5c 68 6f 74 62 61 72 5f 2a 2e 6c 6f 67 } //01 00  \hotbar_*.log
		$a_80_4 = {48 6f 74 62 61 72 2e 63 6f 6d 2f } //Hotbar.com/  02 00 
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 48 62 54 6f 6f 6c 73 5c 48 62 54 6f 6f 6c 73 5c } //01 00  Software\HbTools\HbTools\
		$a_00_6 = {48 62 52 65 73 6f 75 72 63 65 2e 64 6c 6c } //02 00  HbResource.dll
		$a_00_7 = {47 65 74 48 6f 74 62 61 72 42 69 6e 44 69 72 } //02 00  GetHotbarBinDir
		$a_00_8 = {47 65 74 48 6f 74 62 61 72 48 6f 6d 65 44 69 72 } //01 00  GetHotbarHomeDir
		$a_00_9 = {70 61 72 74 6e 65 72 73 2e 68 6f 74 62 61 72 2e 63 6f 6d } //00 00  partners.hotbar.com
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_26{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 57 00 07 80 e8 90 01 04 8b 03 57 ff 75 0c 8b 78 f4 2b f0 e8 90 01 04 3b f7 5f ff 75 0c 77 90 01 01 8d 0c 30 51 ff 75 0c 50 e8 90 00 } //01 00 
		$a_00_1 = {54 42 2e 64 6c 6c } //01 00  TB.dll
		$a_00_2 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } //01 00  enable_ts_logging
		$a_00_3 = {26 63 6f 6d 70 5f 69 64 3d } //01 00  &comp_id=
		$a_00_4 = {73 6f 66 74 77 61 72 65 5c 7a 61 6e 67 6f } //01 00  software\zango
		$a_00_5 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 50 40 73 73 57 25 72 64 00 } //01 00 
		$a_00_6 = {68 6f 6f 6b 2e 64 6c 6c } //01 00  hook.dll
		$a_00_7 = {25 73 20 73 65 61 72 63 68 20 61 73 73 69 73 74 61 6e 74 } //01 00  %s search assistant
		$a_00_8 = {26 61 64 75 72 6c 3d 25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 61 64 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 64 } //02 00  &adurl=%s&errorurl=%s&adid=%s&status=%d
		$a_00_9 = {48 42 4c 69 74 65 } //00 00  HBLite
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_27{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 69 6e 62 61 6c 6c 70 75 62 6c 69 73 68 65 72 6e 65 74 77 6f 72 6b 2e 63 6f 6d } //01 00  pinballpublishernetwork.com
		$a_01_1 = {48 74 54 70 3a 2f 2f 55 43 49 25 32 30 50 61 67 65 25 32 30 44 77 6e 6c 6f 61 64 } //01 00  HtTp://UCI%20Page%20Dwnload
		$a_01_2 = {53 6d 61 72 74 20 53 68 6f 70 70 65 72 20 49 6e 63 00 00 00 5a 61 6e 67 6f 00 00 00 42 6c 69 6e 6b 78 00 00 50 69 6e 62 61 6c 6c 20 43 6f 72 70 6f 72 61 74 69 6f 6e 2e } //01 00 
		$a_00_3 = {73 65 65 6b 6d 6f } //01 00  seekmo
		$a_00_4 = {63 6f 6e 6f 75 74 24 } //01 00  conout$
		$a_00_5 = {2f 42 61 6e 6e 65 72 49 64 3d 24 7b 76 2e 62 61 6e 69 64 7d } //01 00  /BannerId=${v.banid}
		$a_01_6 = {68 6f 74 62 61 72 2e 63 6f 6d } //02 00  hotbar.com
		$a_01_7 = {63 6c 69 63 6b 70 6f 74 61 74 6f 2e 74 76 } //01 00  clickpotato.tv
		$a_01_8 = {2f 53 69 6c 65 6e 74 20 2f 57 65 6c 63 6f 6d 65 3d 66 61 6c 73 65 20 2f 41 66 66 69 6c 69 61 74 65 49 64 3d 24 } //00 00  /Silent /Welcome=false /AffiliateId=$
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_28{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 63 6e 61 6d 65 7c 69 63 76 65 72 73 69 6f 6e 7c 63 73 63 69 64 7c 6d 74 7c 6c 6f 63 61 6c 65 7c 6c 61 6e 67 7c 74 69 64 7c 73 61 69 72 6e 64 } //01 00  icname|icversion|cscid|mt|locale|lang|tid|sairnd
		$a_00_1 = {73 61 69 5f 74 68 65 5f 64 65 62 75 67 5f 77 69 6e 5f 6d 61 69 6e } //01 00  sai_the_debug_win_main
		$a_03_2 = {6d 61 6e 69 66 65 73 74 90 02 01 72 65 61 64 66 61 69 6c 65 64 90 00 } //01 00 
		$a_00_3 = {76 69 63 70 61 72 61 6d 65 74 65 72 73 } //01 00  vicparameters
		$a_03_4 = {69 63 73 6d 90 02 01 61 6e 69 66 65 73 74 00 90 00 } //01 00 
		$a_03_5 = {53 65 74 74 69 6e 67 90 02 02 4b 65 79 90 02 08 44 65 62 75 67 90 00 } //01 00 
		$a_03_6 = {5f 6b 65 79 90 02 02 6f 66 90 02 02 64 65 62 75 67 90 02 02 73 65 74 74 69 6e 67 73 90 00 } //01 00 
		$a_03_7 = {5f 72 65 67 90 02 02 76 61 6c 75 65 90 02 02 6e 61 6d 65 90 02 02 6c 6f 67 90 02 02 65 6e 61 62 6c 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_29{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 08 00 00 64 00 "
		
	strings :
		$a_03_0 = {74 18 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //0a 00 
		$a_02_1 = {76 61 6c 75 65 61 64 64 2f 50 69 6e 67 2f 90 02 05 2e 68 74 6d 90 00 } //0a 00 
		$a_00_2 = {49 00 6e 00 73 00 61 00 74 00 6c 00 6c 00 53 00 74 00 61 00 72 00 74 00 65 00 64 00 } //01 00  InsatllStarted
		$a_02_3 = {64 6f 77 6e 6c 6f 61 64 73 90 02 03 2e 70 6c 61 74 72 69 75 6d 2e 63 6f 6d 90 00 } //01 00 
		$a_02_4 = {64 6f 77 6e 6c 6f 61 64 73 90 02 03 2e 70 69 6e 62 61 6c 6c 63 6f 72 70 2e 63 6f 6d 90 00 } //01 00 
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 73 2f 62 62 2f 62 62 2f 61 61 2e 68 74 6d 00 } //01 00 
		$a_00_6 = {42 00 53 00 41 00 49 00 4d 00 61 00 69 00 6e 00 57 00 69 00 6e 00 } //01 00  BSAIMainWin
		$a_00_7 = {41 00 70 00 70 00 42 00 75 00 6e 00 64 00 6c 00 65 00 72 00 4d 00 61 00 69 00 6e 00 57 00 69 00 6e 00 } //00 00  AppBundlerMainWin
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_30{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 69 73 20 61 20 63 6c 65 61 6e 20 73 79 73 74 65 6d 2e 00 4c 65 61 76 69 6e 67 20 4c 65 67 61 63 79 44 65 74 65 63 74 69 6f 6e } //01 00 
		$a_01_1 = {53 68 6f 70 70 65 72 52 65 70 6f 72 74 20 4f 70 74 20 49 6e 20 52 65 66 75 73 65 64 2e 00 } //01 00  桓灯数割灥牯⁴灏⁴湉删晥獵摥.
		$a_01_2 = {44 65 6c 65 74 65 41 6c 6c 43 6f 6f 6b 69 65 73 00 2a 7a 61 6e 67 6f 2a 2e 74 78 74 } //01 00  敄敬整汁䍬潯楫獥⨀慺杮⩯琮瑸
		$a_01_3 = {6c 65 67 61 63 79 5f 73 68 6f 70 70 65 72 72 65 70 6f 72 74 73 5f 61 66 66 69 64 00 } //01 00  敬慧祣獟潨灰牥敲潰瑲彳晡楦d
		$a_01_4 = {50 69 6e 62 61 6c 6c 20 43 6f 72 70 6f 72 61 74 69 6f 6e 2e 00 } //01 00 
		$a_01_5 = {48 42 48 69 6e 74 53 65 61 72 63 68 54 65 72 6d 46 69 65 6c 64 73 3d } //01 00  HBHintSearchTermFields=
		$a_01_6 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 48 6f 74 62 61 72 20 53 65 61 72 63 68 } //01 00 
		$a_01_7 = {50 61 69 64 20 48 6f 74 62 61 72 20 44 65 74 65 63 74 65 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_31{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {5a 61 6e 67 6f 44 65 62 75 67 57 69 6e 64 6f 77 } //01 00  ZangoDebugWindow
		$a_00_1 = {31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d } //01 00  180solutions.com
		$a_00_2 = {77 77 77 2e 7a 61 6e 67 6f 2e 63 6f 6d 2f 74 62 64 } //01 00  www.zango.com/tbd
		$a_00_3 = {2f 55 70 6c 6f 61 64 73 2f 44 69 72 65 63 74 2f } //01 00  /Uploads/Direct/
		$a_00_4 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f 44 65 62 75 67 53 65 74 74 69 6e 67 73 } //01 00  HKCU\Software\ZangoDebugSettings
		$a_00_5 = {54 68 69 73 20 61 64 20 69 73 20 66 72 6f 6d 20 48 6f 74 62 61 72 20 61 6e 64 20 5a 61 6e 67 6f 2c 20 49 6e 63 2e 20 2d 20 43 6c 69 63 6b 20 68 65 72 65 20 66 6f 72 20 69 6e 66 6f 20 6f 6e 20 68 6f 77 20 79 6f 75 20 67 6f 74 20 48 6f 74 62 61 72 20 53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 2e } //01 00  This ad is from Hotbar and Zango, Inc. - Click here for info on how you got Hotbar Search Assistant.
		$a_00_6 = {48 00 6f 00 74 00 62 00 61 00 72 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 41 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 } //01 00  Hotbar Search Assistant
		$a_00_7 = {48 00 6f 00 74 00 62 00 61 00 72 00 20 00 53 00 65 00 74 00 75 00 70 00 } //01 00  Hotbar Setup
		$a_80_8 = {48 6f 74 62 61 72 2e 63 6f 6d 2f } //Hotbar.com/  00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_32{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 0c 00 00 04 00 "
		
	strings :
		$a_01_0 = {25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 61 64 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 64 } //04 00  %s&errorurl=%s&adid=%s&status=%d
		$a_00_1 = {6f 6e 65 38 74 73 6f 6c 75 74 69 6f 6e 73 70 40 73 73 77 25 72 64 00 } //02 00 
		$a_00_2 = {31 38 30 67 65 74 65 78 65 6e 61 6d 65 00 } //02 00  㠱朰瑥硥湥浡e
		$a_00_3 = {73 6f 66 74 77 61 72 65 5c 7a 61 6e 67 6f } //02 00  software\zango
		$a_01_4 = {31 38 30 43 6c 69 65 6e 74 20 4d 75 6c 74 69 70 6c 65 20 49 6e 73 74 61 6e 63 65 20 4c 6f 63 6b } //02 00  180Client Multiple Instance Lock
		$a_01_5 = {62 69 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2b 61 64 66 6f 72 63 65 2e 69 6d 67 } //02 00  bis.180solutions.com+adforce.img
		$a_01_6 = {26 64 69 64 3d 25 73 26 76 65 72 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d } //02 00  &did=%s&ver=%s&partner_id=
		$a_01_7 = {6d 5f 70 50 6f 70 42 72 6f 77 73 65 72 2d 3e 67 65 74 5f 44 6f 63 75 6d 65 6e 74 28 29 } //01 00  m_pPopBrowser->get_Document()
		$a_01_8 = {61 64 5f 68 69 73 74 6f 72 79 5f 63 6f 75 6e 74 00 } //01 00 
		$a_01_9 = {2f 64 69 73 61 62 6c 65 5f 74 76 5f 61 64 73 3d 6e } //01 00  /disable_tv_ads=n
		$a_01_10 = {68 74 74 70 3a 2f 2f 74 72 69 61 6c 70 61 79 6e 6f } //01 00  http://trialpayno
		$a_01_11 = {41 64 57 65 62 42 72 6f 77 73 65 72 45 76 65 6e 74 73 2e 63 70 70 } //00 00  AdWebBrowserEvents.cpp
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_33{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 00 61 00 70 00 70 00 62 00 75 00 6e 00 64 00 6c 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 } //02 00  .appbundler.net/
		$a_01_1 = {7c 00 61 00 76 00 69 00 72 00 61 00 7c 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 7c 00 61 00 76 00 61 00 73 00 74 00 21 00 7c 00 61 00 76 00 67 00 } //01 00  |avira|antivir|avast!|avg
		$a_01_2 = {54 00 72 00 61 00 63 00 6b 00 65 00 64 00 45 00 76 00 65 00 6e 00 74 00 73 00 2e 00 55 00 52 00 4c 00 } //01 00  TrackedEvents.URL
		$a_01_3 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 52 00 65 00 70 00 6f 00 72 00 74 00 } //01 00  InstallReport
		$a_00_4 = {26 64 65 66 61 75 6c 74 62 72 6f 77 73 65 72 3d } //01 00  &defaultbrowser=
		$a_01_5 = {50 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  Pinball Corporation
		$a_01_6 = {3c 63 73 63 69 64 3e 25 73 3c 2f 63 73 63 69 64 3e } //01 00  <cscid>%s</cscid>
		$a_00_7 = {2e 00 73 00 65 00 63 00 75 00 72 00 65 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 61 00 63 00 63 00 65 00 73 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00  .securewebsiteaccess.com/
		$a_01_8 = {41 64 64 65 64 20 62 79 20 69 63 73 6d 61 6e 69 66 65 73 74 } //02 00  Added by icsmanifest
		$a_00_9 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2e 00 73 00 65 00 65 00 6b 00 6d 00 6f 00 2e 00 63 00 6f 00 6d 00 } //00 00  downloads.seekmo.com
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_34{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 42 43 68 65 63 6b 50 65 72 6d 69 73 73 69 6f 6e 2e 74 78 74 } //01 00  HBCheckPermission.txt
		$a_01_1 = {53 70 61 6d 20 42 6c 6f 63 6b 65 72 20 55 74 69 6c 69 74 79 } //01 00  Spam Blocker Utility
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 70 61 6d 42 6c 6f 63 6b 65 72 55 74 69 6c 69 74 79 } //01 00  C:\Program Files\SpamBlockerUtility
		$a_01_3 = {61 20 73 75 62 73 69 64 69 61 72 79 20 6f 66 20 5a 61 6e 67 6f 2c 20 49 6e 63 } //01 00  a subsidiary of Zango, Inc
		$a_01_4 = {42 79 20 69 6e 73 74 61 6c 6c 69 6e 67 20 74 68 65 20 5a 61 6e 67 6f 20 53 6f 66 74 77 61 72 65 } //01 00  By installing the Zango Software
		$a_01_5 = {6b 65 79 77 6f 72 64 20 73 65 61 72 63 68 20 69 6e 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 61 64 64 72 65 73 73 20 62 61 72 20 61 6e 64 20 63 68 61 6e 67 65 20 6d 79 20 73 65 61 72 63 68 20 61 73 73 69 73 74 61 6e 74 } //01 00  keyword search in Internet Explorer address bar and change my search assistant
		$a_01_6 = {26 49 6e 73 74 61 6c 6c 65 72 3d 31 26 53 79 73 54 69 6d 65 3d } //01 00  &Installer=1&SysTime=
		$a_01_7 = {53 68 6f 70 70 65 72 20 52 65 70 6f 72 74 73 } //01 00  Shopper Reports
		$a_01_8 = {66 6f 72 63 65 50 72 6f 6d 6f 42 79 49 6e 73 74 61 6c 6c 65 72 } //01 00  forcePromoByInstaller
		$a_01_9 = {68 74 74 70 73 3a 2f 2f 73 65 63 75 72 65 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f } //01 00  https://secure.hotbar.com/
		$a_01_10 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 2f 42 72 6f 77 73 69 6e 67 2f 45 6e 64 45 78 65 49 6e 73 74 61 6c 6c 2e 61 73 70 78 } //00 00  Installation/Browsing/EndExeInstall.aspx
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_35{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 24 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsa$i_upg$rade_url
		$a_01_1 = {7c 00 61 00 76 00 69 00 72 00 61 00 7c 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 7c 00 61 00 76 00 61 00 73 00 74 00 21 00 7c 00 61 00 76 00 67 00 7c 00 62 00 69 00 74 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 7c 00 62 00 75 00 6c 00 6c 00 67 00 75 00 61 00 72 00 64 00 7c 00 65 00 72 00 72 00 3a 00 7c 00 63 00 79 00 62 00 65 00 72 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 7c 00 65 00 73 00 65 00 74 00 7c 00 } //01 00  |avira|antivir|avast!|avg|bitdefender|bullguard|err:|cyberdefender|eset|
		$a_01_2 = {43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 72 00 65 00 61 00 64 00 20 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 6d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 3a 00 20 00 25 00 73 00 } //01 00  Cannot read desktop manifest: %s
		$a_01_3 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 73 00 65 00 63 00 75 00 72 00 65 00 77 00 65 00 24 00 62 00 73 00 69 00 74 00 65 00 61 00 63 00 63 00 65 00 73 00 73 00 2e 00 63 00 6f 00 6d 00 } //01 00  install.securewe$bsiteaccess.com
		$a_01_4 = {4f 00 6e 00 53 00 41 00 49 00 56 00 65 00 72 00 69 00 66 00 79 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 28 00 29 00 3a 00 } //01 00  OnSAIVerifyInstall():
		$a_01_5 = {56 00 49 00 43 00 20 00 50 00 61 00 72 00 61 00 6d 00 73 00 3a 00 } //00 00  VIC Params:
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_36{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 24 00 5f 00 75 00 72 00 6c 00 } //01 00  b$sai_upgrade$_url
		$a_01_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2e 00 73 00 65 00 65 00 6b 00 6d 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 61 00 61 00 2f 00 61 00 61 00 2f 00 62 00 62 00 2e 00 68 00 74 00 6d 00 } //01 00  downloads.seekmo.com/downloads/aa/aa/bb.htm
		$a_01_2 = {61 00 76 00 69 00 72 00 61 00 7c 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 7c 00 61 00 76 00 61 00 73 00 74 00 21 00 7c 00 61 00 76 00 67 00 7c 00 62 00 69 00 74 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 7c 00 62 00 75 00 6c 00 6c 00 67 00 75 00 61 00 72 00 64 00 7c 00 65 00 72 00 72 00 3a 00 7c 00 63 00 79 00 62 00 65 00 72 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 7c 00 65 00 73 00 65 00 74 00 7c 00 6e 00 65 00 74 00 } //01 00  avira|antivir|avast!|avg|bitdefender|bullguard|err:|cyberdefender|eset|net
		$a_01_3 = {5f 00 73 00 65 00 74 00 75 00 70 00 5f 00 61 00 70 00 70 00 5f 00 77 00 69 00 6e 00 5f 00 63 00 6c 00 61 00 73 00 73 00 5f 00 30 00 31 00 5f 00 } //01 00  _setup_app_win_class_01_
		$a_01_4 = {73 00 61 00 69 00 5f 00 74 00 65 00 73 00 74 00 3d 00 25 00 6c 00 75 00 } //01 00  sai_test=%lu
		$a_01_5 = {73 00 65 00 63 00 75 00 72 00 65 00 77 00 65 00 90 00 02 00 01 00 62 00 73 00 69 00 74 00 65 00 61 00 63 00 63 00 65 00 73 00 73 00 2e 00 63 00 6f 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_37{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0f 00 00 0a 00 "
		
	strings :
		$a_02_0 = {54 68 69 73 20 90 02 04 61 64 90 02 04 69 73 20 66 72 6f 6d 20 48 6f 74 62 61 72 90 00 } //0a 00 
		$a_00_1 = {68 00 6f 00 74 00 62 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 } //05 00  hotbar.com
		$a_00_2 = {64 6f 77 6e 6c 6f 61 64 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f } //05 00  downloads.180solutions.com/
		$a_00_3 = {25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 61 64 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 64 } //05 00  %s&errorurl=%s&adid=%s&status=%d
		$a_00_4 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 50 40 73 73 57 25 72 64 00 } //01 00 
		$a_00_5 = {25 73 20 53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //01 00  %s Search Assistant
		$a_00_6 = {2f 64 69 73 61 62 6c 65 5f 74 76 5f 61 64 73 3d 6e } //01 00  /disable_tv_ads=n
		$a_00_7 = {61 74 74 65 6d 70 74 20 74 6f 20 73 68 6f 77 20 61 6e 20 61 64 20 74 69 6d 65 64 20 6f 75 74 00 } //01 00 
		$a_00_8 = {77 6d 5f 73 68 6f 77 5f 61 64 20 72 65 71 75 65 73 74 20 72 65 63 65 69 76 65 64 00 } //01 00  海獟潨彷摡爠煥敵瑳爠捥楥敶d
		$a_00_9 = {70 6f 70 70 69 6e 67 20 61 20 47 41 44 20 61 64 20 2d 20 61 64 20 69 64 20 28 25 73 29 20 20 6b 65 79 77 6f 72 64 20 69 64 20 28 25 73 29 } //01 00  popping a GAD ad - ad id (%s)  keyword id (%s)
		$a_00_10 = {63 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 61 64 73 2e 61 73 70 78 00 } //01 00 
		$a_00_11 = {61 64 5f 68 69 73 74 6f 72 79 5f 63 6f 75 6e 74 00 } //01 00 
		$a_00_12 = {73 6f 66 74 77 61 72 65 5c 7a 61 6e 67 6f } //01 00  software\zango
		$a_00_13 = {31 38 30 67 65 74 65 78 65 6e 61 6d 65 00 } //01 00  㠱朰瑥硥湥浡e
		$a_00_14 = {2e 5c 53 6f 75 72 63 65 5c 31 38 30 53 41 2e 63 70 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_38{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 74 00 74 00 70 00 2f 00 56 00 45 00 52 00 5f 00 53 00 54 00 52 00 5f 00 43 00 4f 00 4d 00 4d 00 41 00 } //01 00  Http/VER_STR_COMMA
		$a_01_1 = {25 00 63 00 76 00 65 00 72 00 3d 00 25 00 73 00 26 00 72 00 6e 00 64 00 3d 00 25 00 6c 00 75 00 } //01 00  %cver=%s&rnd=%lu
		$a_01_2 = {25 00 64 00 2f 00 25 00 64 00 2f 00 25 00 30 00 34 00 64 00 20 00 25 00 64 00 3a 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 20 00 25 00 73 00 } //01 00  %d/%d/%04d %d:%02d:%02d %s
		$a_01_3 = {25 00 30 00 34 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 2e 00 25 00 30 00 33 00 75 00 2e 00 25 00 75 00 } //01 00  %04d%02d%02d%02d%02d%02d.%03u.%u
		$a_01_4 = {56 00 49 00 43 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 4c 00 69 00 73 00 74 00 } //01 00  VICParameterNameList
		$a_01_5 = {2f 00 62 00 73 00 61 00 69 00 74 00 65 00 73 00 74 00 3d 00 25 00 6c 00 75 00 20 00 28 00 30 00 78 00 25 00 78 00 29 00 } //01 00  /bsaitest=%lu (0x%x)
		$a_01_6 = {53 00 41 00 49 00 53 00 65 00 74 00 48 00 6f 00 74 00 6b 00 65 00 79 00 } //01 00  SAISetHotkey
		$a_01_7 = {4c 00 61 00 75 00 6e 00 63 00 68 00 20 00 27 00 25 00 73 00 27 00 20 00 69 00 6e 00 20 00 25 00 73 00 2c 00 20 00 70 00 61 00 74 00 68 00 6b 00 65 00 79 00 3d 00 25 00 64 00 2c 00 20 00 73 00 74 00 61 00 74 00 75 00 73 00 20 00 25 00 73 00 } //02 00  Launch '%s' in %s, pathkey=%d, status %s
		$a_01_8 = {48 00 4b 00 43 00 55 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 70 00 70 00 62 00 75 00 6e 00 64 00 6c 00 65 00 72 00 5c 00 64 00 65 00 62 00 75 00 67 00 77 00 69 00 6e 00 6d 00 61 00 69 00 6e 00 } //00 00  HKCU\software\Appbundler\debugwinmain
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_39{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 12 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5f 73 61 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 43 6c 69 65 6e 74 53 41 48 6f 6f 6b 2e 70 64 62 } //05 00  _sa\bin\Release\ClientSAHook.pdb
		$a_03_1 = {65 6e 61 62 6c 65 90 02 02 74 73 90 02 02 6c 6f 67 90 00 } //05 00 
		$a_00_2 = {31 38 30 42 42 43 6c 61 73 73 } //05 00  180BBClass
		$a_00_3 = {31 38 30 75 6e 69 6e 73 74 61 6c 6c 65 72 } //05 00  180uninstaller
		$a_00_4 = {7a 61 6e 67 6f 75 6e 69 6e 73 74 61 6c 6c 65 72 } //05 00  zangouninstaller
		$a_00_5 = {31 38 30 73 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //05 00  180search Assistant
		$a_00_6 = {31 38 30 24 73 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //05 00  180$search Assistant
		$a_00_7 = {31 38 24 30 73 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //05 00  18$0search Assistant
		$a_00_8 = {31 24 38 30 73 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //05 00  1$80search Assistant
		$a_00_9 = {43 48 6f 6f 6b 65 64 57 69 6e 64 6f 77 4d 53 4e 39 2e 63 70 70 } //01 00  CHookedWindowMSN9.cpp
		$a_00_10 = {68 6f 6f 6b 5f 64 6c 6c 3a 20 61 64 20 70 72 6f 70 73 20 74 69 6d 65 72 20 69 73 20 6b 69 6c 6c 65 64 20 6f 6e 20 69 65 20 77 69 6e 64 6f 77 } //01 00  hook_dll: ad props timer is killed on ie window
		$a_00_11 = {68 6f 6f 6b 5f 64 6c 6c 3a 20 75 73 65 72 20 73 75 72 66 69 6e 67 20 61 77 61 79 20 66 72 6f 6d 20 6f 72 69 67 69 6e 61 6c 20 61 64 } //01 00  hook_dll: user surfing away from original ad
		$a_00_12 = {6e 6f 72 6d 61 6c 20 69 66 20 69 74 27 73 20 6e 6f 74 20 6f 6e 20 61 6e 20 61 64 20 49 45 } //01 00  normal if it's not on an ad IE
		$a_00_13 = {68 6f 6f 6b 5f 64 6c 6c 3a 20 68 69 64 65 20 61 64 } //01 00  hook_dll: hide ad
		$a_00_14 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 53 74 61 72 74 20 74 6f 20 63 68 65 63 6b 20 66 6f 72 20 68 69 64 65 20 41 64 } //01 00  HOOK_DLL: Start to check for hide Ad
		$a_00_15 = {68 6f 6f 6b 5f 64 6c 6c 3a 20 61 64 20 70 72 6f 63 65 73 73 20 69 64 20 28 30 78 25 30 38 78 29 20 65 71 75 61 6c 73 } //01 00  hook_dll: ad process id (0x%08x) equals
		$a_00_16 = {68 6f 6f 6b 5f 64 6c 6c 3a 20 73 65 6e 64 69 6e 67 20 6e 65 77 20 75 72 6c 20 6d 65 73 73 61 67 65 20 74 6f 20 73 65 61 72 63 68 20 61 73 73 69 73 74 61 6e 74 20 77 69 6e 64 6f 77 28 30 78 25 30 38 78 29 } //01 00  hook_dll: sending new url message to search assistant window(0x%08x)
		$a_00_17 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 48 69 64 65 20 49 45 28 41 64 29 20 77 69 6e 64 6f 77 20 28 30 78 25 78 29 } //00 00  HOOK_DLL: Hide IE(Ad) window (0x%x)
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_40{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 1c 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 6e 65 38 74 73 6f 6c 75 74 69 6f 6e 73 } //01 00  one8tsolutions
		$a_00_1 = {2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d } //01 00  .180solutions.com
		$a_00_2 = {2e 68 69 70 70 6f 67 65 65 6b 2e 63 6f 6d } //01 00  .hippogeek.com
		$a_00_3 = {2e 54 65 65 76 65 65 57 61 74 63 68 2e 63 6f 6d } //01 00  .TeeveeWatch.com
		$a_00_4 = {2e 67 69 67 67 6c 69 6e 67 67 61 6d 65 73 2e 63 6f 6d } //01 00  .gigglinggames.com
		$a_01_5 = {26 64 69 64 3d 25 73 26 76 65 72 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d } //01 00  &did=%s&ver=%s&partner_id=
		$a_01_6 = {26 25 73 3d 25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 73 74 61 74 75 73 3d 25 64 26 61 64 69 64 3d 25 73 } //01 00  &%s=%s&errorurl=%s&status=%d&adid=%s
		$a_01_7 = {64 69 64 3d 25 73 26 6d 74 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d 25 73 } //01 00  did=%s&mt=%s&partner_id=%s
		$a_01_8 = {6d 74 3d 25 73 26 64 69 64 3d 25 73 26 75 69 5f 73 6f 75 72 63 65 3d 25 73 26 75 69 5f 69 74 65 6d 5f 69 64 3d 25 73 } //01 00  mt=%s&did=%s&ui_source=%s&ui_item_id=%s
		$a_01_9 = {64 69 64 3d 25 73 26 6e 61 6d 65 3d 25 73 26 6d 74 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d 25 73 } //01 00  did=%s&name=%s&mt=%s&partner_id=%s
		$a_01_10 = {6d 74 3d 25 73 26 64 69 64 3d 25 73 26 6e 61 6d 65 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d 25 73 } //01 00  mt=%s&did=%s&name=%s&partner_id=%s
		$a_01_11 = {6d 74 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d 25 73 26 64 69 64 3d 25 73 26 6e 61 6d 65 3d 25 73 } //01 00  mt=%s&partner_id=%s&did=%s&name=%s
		$a_01_12 = {26 25 73 3d 25 73 26 73 74 61 74 75 73 3d 25 64 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 61 64 69 64 3d 25 73 } //01 00  &%s=%s&status=%d&errorurl=%s&adid=%s
		$a_01_13 = {26 25 73 3d 25 73 26 73 74 61 74 75 73 3d 25 64 26 61 64 69 64 3d 25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 } //01 00  &%s=%s&status=%d&adid=%s&errorurl=%s
		$a_01_14 = {64 69 64 3d 25 73 26 6d 74 3d 25 73 26 75 69 5f 69 74 65 6d 5f 69 64 3d 25 73 26 75 69 5f 73 6f 75 72 63 65 3d 25 73 } //01 00  did=%s&mt=%s&ui_item_id=%s&ui_source=%s
		$a_01_15 = {61 64 69 64 3d 25 6c 75 26 6b 77 69 64 3d 25 6c 75 26 61 64 74 69 6d 65 3d 25 73 } //01 00  adid=%lu&kwid=%lu&adtime=%s
		$a_01_16 = {6d 74 3d 25 73 26 6e 61 6d 65 3d 25 73 26 70 61 72 74 6e 65 72 5f 69 64 3d 25 73 26 64 69 64 3d 25 73 } //01 00  mt=%s&name=%s&partner_id=%s&did=%s
		$a_01_17 = {61 64 5f 68 69 73 74 6f 72 79 5f 63 6f 75 6e 74 00 } //01 00 
		$a_01_18 = {64 69 73 61 62 6c 65 5f 74 76 5f 61 } //01 00  disable_tv_a
		$a_01_19 = {26 64 69 73 61 62 6c 65 5f 61 64 73 3d 79 } //01 00  &disable_ads=y
		$a_01_20 = {61 64 5f 54 61 6b 65 66 6f 63 75 73 00 } //01 00 
		$a_01_21 = {6e 6f 5f 61 64 5f 72 65 71 5f 6f 6e 5f 62 6f 64 79 } //01 00  no_ad_req_on_body
		$a_01_22 = {78 78 5f 64 69 64 5f 78 78 00 } //01 00  硸摟摩硟x
		$a_01_23 = {78 78 5f 75 63 69 5f 73 69 67 5f 78 78 00 } //01 00  硸畟楣獟杩硟x
		$a_03_24 = {65 6e 61 62 6c 65 90 02 02 74 73 90 02 02 6c 6f 67 90 00 } //01 00 
		$a_01_25 = {41 64 57 65 62 42 72 6f 77 73 65 72 45 76 65 6e 74 73 2e 63 70 70 } //01 00  AdWebBrowserEvents.cpp
		$a_01_26 = {79 6f 75 20 6d 61 79 20 72 65 63 65 69 76 65 20 41 64 75 6c 74 2d 6f 72 69 65 6e 74 65 64 20 61 64 73 } //01 00  you may receive Adult-oriented ads
		$a_01_27 = {61 70 70 6c 69 63 61 74 69 6f 6e 73 20 64 69 73 74 72 69 62 75 74 65 64 20 62 79 20 50 6c 61 74 72 69 75 6d 2e } //00 00  applications distributed by Platrium.
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_41{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 18 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5f 73 61 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 43 6c 69 65 6e 74 53 41 43 42 2e 70 64 62 00 } //05 00 
		$a_01_1 = {57 65 62 20 62 72 6f 77 73 65 72 20 63 72 65 61 74 65 20 66 61 69 6c 65 64 2c 20 68 72 3d 30 78 25 30 38 58 2e 00 } //05 00 
		$a_01_2 = {57 65 62 20 25 73 20 63 72 65 61 74 65 20 66 61 69 6c 65 64 2c 20 68 72 3d 30 78 25 30 38 58 2e 00 } //05 00 
		$a_01_3 = {57 65 25 73 61 74 65 20 66 61 69 6c 65 64 2c 20 68 72 3d 30 78 25 30 38 58 2e 00 } //05 00 
		$a_01_4 = {57 65 62 25 73 61 74 65 20 66 61 69 6c 65 64 2c 20 68 72 3d 30 78 25 30 38 58 2e 00 } //05 00  敗╢慳整映楡敬Ɽ栠㵲砰〥堸.
		$a_01_5 = {41 64 20 64 65 6c 69 76 65 72 65 64 20 69 6e 20 63 6c 69 65 6e 74 20 62 72 6f 77 73 65 72 2c 20 75 72 6c 3a 20 25 73 2c 20 61 64 69 64 3a 20 25 73 2c 20 6b 65 79 77 6f 72 64 69 64 3a 20 25 73 2e 00 } //05 00 
		$a_01_6 = {41 64 20 25 73 20 69 6e 20 63 6c 69 65 6e 74 20 62 72 6f 77 73 65 72 2c 20 75 72 6c 3a 20 25 73 2c 20 61 64 69 64 3a 20 25 73 2c 20 6b 65 79 77 6f 72 64 69 64 3a 20 25 73 2e 00 } //05 00 
		$a_01_7 = {41 25 73 76 65 72 65 64 20 69 6e 20 63 6c 69 65 6e 74 20 62 72 25 73 72 6c 3a 20 25 73 2c 20 61 64 69 64 3a 20 25 73 2c 20 6b 65 79 77 6f 72 64 69 64 3a 20 25 73 2e 00 } //05 00 
		$a_01_8 = {34 30 34 20 73 65 61 72 63 68 20 55 52 4c 20 64 6f 65 73 20 6e 6f 74 20 63 6f 6e 74 61 69 6e 20 61 20 76 61 6c 69 64 20 73 65 61 72 63 68 20 74 65 72 6d 2c 20 73 65 61 72 63 68 55 52 4c 3a 20 25 73 2e 00 } //05 00 
		$a_01_9 = {34 00 30 00 34 00 20 00 73 00 65 00 61 00 72 00 63 00 68 00 20 00 74 00 6f 00 6b 00 65 00 6e 00 20 00 27 00 25 00 73 00 27 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 69 00 6e 00 20 00 73 00 65 00 61 00 72 00 63 00 68 00 55 00 52 00 4c 00 20 00 27 00 25 00 73 00 27 00 } //05 00  404 search token '%s' not found in searchURL '%s'
		$a_01_10 = {41 64 20 64 65 6c 69 76 65 72 20 74 69 6d 65 6f 75 74 20 69 6e 20 63 6c 69 65 6e 74 20 62 72 6f 77 73 65 72 2c 20 61 64 69 64 3a 20 25 73 2e 00 } //05 00 
		$a_01_11 = {41 00 64 00 20 00 64 00 65 00 6c 00 69 00 76 00 65 00 72 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 69 00 6e 00 20 00 63 00 6c 00 69 00 65 00 6e 00 74 00 20 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 2c 00 20 00 61 00 64 00 69 00 64 00 3a 00 20 00 25 00 73 00 2e 00 00 00 } //05 00 
		$a_01_12 = {64 00 65 00 6c 00 69 00 76 00 65 00 72 00 00 00 6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 5f 00 69 00 64 00 00 00 } //05 00 
		$a_01_13 = {6b 00 65 00 79 00 77 00 6f 00 72 00 64 00 5f 00 69 00 64 00 00 00 00 00 61 00 64 00 5f 00 69 00 64 00 00 00 } //01 00 
		$a_01_14 = {63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 2f 00 61 00 64 00 5f 00 6c 00 61 00 62 00 65 00 6c 00 } //01 00  controls/ad_label
		$a_01_15 = {61 00 64 00 5f 00 53 00 65 00 74 00 52 00 65 00 66 00 65 00 72 00 65 00 72 00 } //01 00  ad_SetReferer
		$a_01_16 = {61 00 64 00 5f 00 46 00 75 00 6c 00 6c 00 73 00 63 00 72 00 65 00 65 00 6e 00 } //01 00  ad_Fullscreen
		$a_01_17 = {61 00 64 00 5f 00 54 00 61 00 6b 00 65 00 66 00 6f 00 63 00 75 00 73 00 } //01 00  ad_Takefocus
		$a_01_18 = {61 00 64 00 5f 00 61 00 6e 00 69 00 6d 00 61 00 74 00 65 00 } //01 00  ad_animate
		$a_01_19 = {61 00 64 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  ad_source_url
		$a_01_20 = {61 00 64 00 5f 00 73 00 63 00 70 00 74 00 } //01 00  ad_scpt
		$a_01_21 = {61 00 64 00 24 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  ad$_source_url
		$a_01_22 = {61 00 24 00 64 00 5f 00 53 00 65 00 74 00 24 00 52 00 65 00 66 00 65 00 72 00 65 00 72 00 } //01 00  a$d_Set$Referer
		$a_01_23 = {61 00 24 00 64 00 5f 00 46 00 75 00 6c 00 6c 00 73 00 24 00 63 00 72 00 65 00 65 00 6e 00 } //00 00  a$d_Fulls$creen
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_42{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 59 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 49 6e 73 61 74 6c 6c 00 } //02 00 
		$a_01_1 = {49 6e 73 61 74 6c 6c 53 74 61 72 74 65 64 00 } //02 00 
		$a_03_2 = {80 39 00 74 18 8b 7d 90 01 01 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_01_3 = {8b c1 32 c9 88 88 00 01 00 00 88 88 01 01 00 00 88 88 02 01 00 00 c3 } //02 00 
		$a_03_4 = {0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_01_5 = {42 53 41 49 5f 4d 61 69 6e 57 69 6e 00 } //01 00 
		$a_01_6 = {42 53 41 49 5f 42 75 69 6c 64 } //01 00  BSAI_Build
		$a_01_7 = {42 53 41 49 4d 61 69 6e 5c 73 6f 75 72 63 65 5c 52 65 6c 65 61 73 65 } //01 00  BSAIMain\source\Release
		$a_01_8 = {42 53 41 49 32 5c 73 6f 75 72 63 65 5c 52 65 6c 65 61 73 65 } //01 00  BSAI2\source\Release
		$a_01_9 = {61 6e 74 69 66 72 61 75 64 75 63 69 74 69 6d 65 72 00 } //01 00  湡楴牦畡畤楣楴敭r
		$a_01_10 = {73 61 69 74 65 73 74 } //01 00  saitest
		$a_01_11 = {73 61 69 5f 64 65 62 75 67 5f 77 69 6e } //01 00  sai_debug_win
		$a_01_12 = {73 61 69 72 6e 64 7c } //01 00  sairnd|
		$a_03_13 = {65 6e 61 62 6c 65 90 02 02 74 73 90 02 02 6c 6f 67 90 00 } //01 00 
		$a_03_14 = {65 6e 61 62 6c 65 90 02 02 74 68 65 90 02 02 74 73 90 02 02 6c 6f 67 90 00 } //01 00 
		$a_03_15 = {65 6e 61 62 6c 65 90 02 02 6c 6f 67 67 69 6e 67 90 02 02 72 65 67 76 61 6c 75 65 6e 61 6d 65 90 00 } //01 00 
		$a_01_16 = {65 6e 61 62 6c 65 5f 6c 6f 67 5f 74 68 65 5f 72 65 67 5f 76 61 6c 75 65 5f 6e 61 6d 65 00 } //01 00  湥扡敬江杯瑟敨牟来癟污敵湟浡e
		$a_03_17 = {64 65 62 75 67 90 02 02 73 65 74 74 69 6e 67 73 90 02 02 72 65 67 6b 65 79 6e 61 6d 65 90 00 } //01 00 
		$a_03_18 = {72 65 67 5f 6b 65 79 90 02 01 6e 61 6d 65 5f 66 6f 72 90 02 05 64 65 62 75 67 90 02 02 73 65 74 74 69 6e 67 73 90 00 } //01 00 
		$a_01_19 = {74 68 65 5f 72 65 67 6b 65 79 5f 6f 66 5f 64 65 62 75 67 5f 73 65 74 74 69 6e 67 73 00 } //01 00 
		$a_03_20 = {6c 6f 67 5f 65 6e 61 62 6c 65 5f 90 02 04 72 65 67 5f 76 61 6c 75 65 90 02 02 6e 61 6d 65 90 00 } //01 00 
		$a_03_21 = {6c 6f 67 67 69 6e 67 90 02 02 65 6e 61 62 6c 65 90 02 02 72 65 67 90 02 02 76 61 6c 75 65 90 02 02 6e 61 6d 65 90 00 } //01 00 
		$a_03_22 = {74 68 65 5f 64 65 62 75 67 90 02 02 73 65 74 74 69 6e 67 73 5f 72 65 67 5f 6b 65 79 6e 61 6d 65 90 00 } //01 00 
		$a_01_23 = {73 61 69 5f 74 68 65 5f 64 65 62 75 67 5f 77 69 6e 5f 6d 61 69 6e } //01 00  sai_the_debug_win_main
		$a_01_24 = {4b 65 79 5f 44 65 62 75 67 5f 53 65 74 74 69 6e 67 00 } //01 00  敋役敄畢彧敓瑴湩g
		$a_01_25 = {54 68 65 5f 44 65 62 75 67 5f 53 65 74 74 69 6e 67 5f 4b 65 79 00 } //01 00  桔彥敄畢彧敓瑴湩彧敋y
		$a_01_26 = {53 41 49 53 65 74 48 6f 74 6b 65 79 00 } //01 00 
		$a_01_27 = {76 69 63 70 61 72 61 6d } //01 00  vicparam
		$a_01_28 = {76 69 63 5f 70 61 72 61 6d } //01 00  vic_param
		$a_01_29 = {70 61 72 61 6d 65 74 65 72 73 5f 6f 66 5f 76 69 63 } //01 00  parameters_of_vic
		$a_01_30 = {70 61 72 61 6d 73 5f 6f 66 5f 76 69 63 } //01 00  params_of_vic
		$a_01_31 = {76 69 63 70 70 6e 73 6b 69 70 } //01 00  vicppnskip
		$a_01_32 = {76 69 63 5f 70 70 6e 73 6b 69 70 } //01 00  vic_ppnskip
		$a_01_33 = {76 69 63 5f 70 70 6e 5f 73 6b 69 70 } //01 00  vic_ppn_skip
		$a_01_34 = {76 69 63 5f 73 6b 69 70 70 70 6e } //01 00  vic_skipppn
		$a_01_35 = {76 69 63 5f 73 6b 69 70 5f 70 70 6e } //01 00  vic_skip_ppn
		$a_01_36 = {76 69 63 70 70 6e 5f 73 6b 69 70 } //01 00  vicppn_skip
		$a_01_37 = {76 69 63 73 6b 69 70 5f 70 70 6e } //01 00  vicskip_ppn
		$a_01_38 = {76 69 63 73 6b 69 70 70 70 6e } //01 00  vicskipppn
		$a_01_39 = {74 68 65 5f 76 69 63 70 70 6e 5f 73 6b 69 70 } //01 00  the_vicppn_skip
		$a_03_40 = {70 70 6e 5f 76 69 63 90 02 01 73 6b 69 70 90 00 } //01 00 
		$a_01_41 = {70 70 6e 5f 73 6b 69 70 5f 76 69 63 } //01 00  ppn_skip_vic
		$a_01_42 = {70 70 6e 73 6b 69 70 5f 76 69 63 } //01 00  ppnskip_vic
		$a_01_43 = {70 70 6e 73 6b 69 70 76 69 63 } //01 00  ppnskipvic
		$a_01_44 = {70 70 6e 5f 73 6b 69 70 76 69 63 } //01 00  ppn_skipvic
		$a_01_45 = {70 70 6e 76 69 63 73 6b 69 70 } //01 00  ppnvicskip
		$a_01_46 = {70 70 6e 76 69 63 5f 74 68 65 5f 73 6b 69 70 } //01 00  ppnvic_the_skip
		$a_01_47 = {70 70 6e 5f 74 68 65 76 69 63 73 6b 69 70 } //01 00  ppn_thevicskip
		$a_01_48 = {70 70 6e 5f 74 68 65 5f 76 69 63 73 6b 69 70 } //01 00  ppn_the_vicskip
		$a_01_49 = {73 6b 69 70 76 69 63 70 70 6e } //01 00  skipvicppn
		$a_01_50 = {73 6b 69 70 5f 70 70 6e 76 69 63 } //01 00  skip_ppnvic
		$a_01_51 = {73 6b 69 70 5f 70 70 6e 5f 76 69 63 } //01 00  skip_ppn_vic
		$a_01_52 = {73 6b 69 70 5f 76 69 63 5f 70 70 6e 00 } //01 00 
		$a_01_53 = {73 6b 69 70 76 69 63 5f 70 70 6e } //01 00  skipvic_ppn
		$a_01_54 = {70 70 6e 76 69 63 5f 73 6b 69 70 } //01 00  ppnvic_skip
		$a_01_55 = {73 6b 69 70 70 70 6e 76 69 63 } //01 00  skipppnvic
		$a_01_56 = {73 6b 69 70 70 70 6e 5f 76 69 63 } //01 00  skipppn_vic
		$a_01_57 = {70 70 6e 76 69 63 74 68 65 5f 73 6b 69 70 } //01 00  ppnvicthe_skip
		$a_01_58 = {70 70 6e 5f 76 69 63 74 68 65 5f 73 6b 69 70 } //01 00  ppn_victhe_skip
		$a_01_59 = {70 70 6e 5f 76 69 63 5f 74 68 65 5f 73 6b 69 70 } //01 00  ppn_vic_the_skip
		$a_00_60 = {26 62 6e 61 6d 65 3d 26 62 76 65 72 3d 26 76 65 72 3d 26 6d 74 3d 30 30 55 4e } //01 00  &bname=&bver=&ver=&mt=00UN
		$a_00_61 = {26 62 6e 61 6d 65 3d 26 62 76 65 72 3d 26 76 65 72 3d 26 6d 74 3d 30 30 55 4b } //01 00  &bname=&bver=&ver=&mt=00UK
		$a_00_62 = {26 62 6e 61 6d 65 3d 26 62 76 65 72 3d 26 76 65 72 3d 30 2e 30 2e 30 2e 30 26 6d 74 3d 30 30 } //01 00  &bname=&bver=&ver=0.0.0.0&mt=00
		$a_00_63 = {26 62 76 65 72 3d 26 76 65 72 3d 30 2e 30 2e 30 2e 30 26 6d 74 3d 30 30 4e 4b 4f 57 } //01 00  &bver=&ver=0.0.0.0&mt=00NKOW
		$a_02_64 = {26 62 6e 61 6d 65 3d 26 65 69 64 3d 90 01 04 26 62 76 65 72 3d 26 76 65 72 3d 26 6d 74 3d 30 30 4e 90 00 } //01 00 
		$a_02_65 = {26 62 6e 61 6d 65 3d 26 65 69 64 3d 90 01 04 26 62 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 31 90 00 } //01 00 
		$a_02_66 = {26 62 6e 61 6d 65 3d 26 65 69 64 3d 90 01 04 26 75 70 67 3d 6e 26 62 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 31 90 00 } //01 00 
		$a_02_67 = {26 62 6e 61 6d 65 3d 26 65 69 64 3d 90 01 04 26 68 64 69 64 3d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 2d 30 30 26 75 70 67 3d 6e 26 62 76 65 72 3d 90 00 } //01 00 
		$a_03_68 = {7c 63 73 63 69 64 7c 90 02 10 68 64 69 64 7c 6d 74 90 00 } //01 00 
		$a_00_69 = {6d 74 7c 6c 6f 63 61 6c 65 7c 6c 61 6e 67 7c 74 69 64 7c 73 61 69 72 6e 64 } //01 00  mt|locale|lang|tid|sairnd
		$a_00_70 = {6d 74 7c 6c 6f 63 61 6c 65 7c 63 73 63 69 64 7c 74 69 64 7c 73 61 69 72 6e 64 } //01 00  mt|locale|cscid|tid|sairnd
		$a_00_71 = {6c 61 6e 67 7c 74 69 64 7c 69 63 76 65 72 73 69 6f 6e 7c 73 61 69 72 6e 64 } //01 00  lang|tid|icversion|sairnd
		$a_00_72 = {74 69 64 7c 69 63 76 65 72 73 69 6f 6e 7c 69 63 6e 61 6d 65 7c 73 61 69 72 6e 64 } //01 00  tid|icversion|icname|sairnd
		$a_00_73 = {63 73 63 69 64 7c 74 69 64 7c 6c 61 6e 67 7c 73 61 69 72 6e 64 } //01 00  cscid|tid|lang|sairnd
		$a_00_74 = {69 63 76 65 72 73 69 6f 6e 7c 69 63 6e 61 6d 65 7c 6c 61 6e 67 7c 73 61 69 72 6e 64 } //01 00  icversion|icname|lang|sairnd
		$a_00_75 = {74 69 64 7c 6c 6f 63 61 6c 65 7c 69 63 6e 61 6d 65 7c 6c 61 6e 67 7c 73 61 69 72 6e 64 } //01 00  tid|locale|icname|lang|sairnd
		$a_00_76 = {74 69 64 7c 69 63 6e 61 6d 65 7c 6c 6f 63 61 6c 65 7c 6c 61 6e 67 7c 73 61 69 72 6e 64 } //01 00  tid|icname|locale|lang|sairnd
		$a_00_77 = {74 69 64 7c 69 63 6e 61 6d 65 7c 6c 61 6e 67 7c 6c 6f 63 61 6c 65 7c 73 61 69 72 6e 64 } //01 00  tid|icname|lang|locale|sairnd
		$a_00_78 = {63 73 63 69 64 7c 74 69 64 7c 69 63 6e 61 6d 65 7c 6c 61 6e 67 7c 73 61 69 72 6e 64 } //01 00  cscid|tid|icname|lang|sairnd
		$a_00_79 = {69 63 6e 61 6d 65 7c 6c 6f 63 61 6c 65 7c 63 73 63 69 64 7c 74 69 64 7c 73 61 69 72 6e 64 } //01 00  icname|locale|cscid|tid|sairnd
		$a_00_80 = {69 63 6e 61 6d 65 7c 6c 6f 63 61 6c 65 7c 74 69 64 7c 63 73 63 69 64 7c 73 61 69 72 6e 64 } //01 00  icname|locale|tid|cscid|sairnd
		$a_00_81 = {6d 74 7c 69 63 6e 61 6d 65 7c 6c 6f 63 61 6c 65 7c 74 69 64 7c 73 61 69 72 6e 64 } //01 00  mt|icname|locale|tid|sairnd
		$a_00_82 = {6c 61 6e 67 7c 6d 74 7c 69 63 6e 61 6d 65 7c 6c 6f 63 61 6c 65 7c 73 61 69 72 6e 64 } //01 00  lang|mt|icname|locale|sairnd
		$a_00_83 = {69 63 76 65 72 73 69 6f 6e 7c 6c 61 6e 67 7c 6d 74 7c 69 63 6e 61 6d 65 7c 73 61 69 72 6e 64 } //01 00  icversion|lang|mt|icname|sairnd
		$a_00_84 = {63 73 63 69 64 7c 69 63 76 65 72 73 69 6f 6e 7c 6c 61 6e 67 7c 6d 74 7c 73 61 69 72 6e 64 } //01 00  cscid|icversion|lang|mt|sairnd
		$a_03_85 = {6d 61 6e 69 66 65 73 74 90 02 01 72 65 61 64 66 61 69 6c 65 64 90 00 } //01 00 
		$a_01_86 = {62 00 73 00 61 00 69 00 74 00 65 00 73 00 74 00 } //01 00  bsaitest
		$a_03_87 = {25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 25 30 33 90 02 01 75 2e 25 90 02 03 75 00 90 00 } //01 00 
		$a_01_88 = {53 00 41 00 49 00 53 00 65 00 74 00 48 00 6f 00 74 00 6b 00 65 00 79 00 } //00 00  SAISetHotkey
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_43{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 4e 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6e 61 6d 65 3d 26 62 76 65 72 3d 26 6d 74 3d 30 30 30 30 30 30 26 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 74 69 64 3d 26 75 70 67 3d 26 } //01 00  bname=&bver=&mt=000000&ver=&time=-001/-1/-1%20-1:-1:-&tid=&upg=&
		$a_01_1 = {62 76 65 72 3d 26 62 6e 61 6d 65 3d 26 6d 74 3d 30 30 30 30 30 30 26 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 74 69 64 3d 26 75 70 67 3d 26 } //01 00  bver=&bname=&mt=000000&ver=&time=-001/-1/-1%20-1:-1:-&tid=&upg=&
		$a_01_2 = {74 69 64 3d 26 62 76 65 72 3d 26 62 6e 61 6d 65 3d 26 6d 74 3d 30 30 30 30 30 30 26 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 75 70 67 3d 26 } //01 00  tid=&bver=&bname=&mt=000000&ver=&time=-001/-1/-1%20-1:-1:-&upg=&
		$a_01_3 = {62 76 65 72 3d 26 74 69 64 3d 26 6d 74 3d 30 30 30 30 30 30 26 62 6e 61 6d 65 3d 26 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 75 70 67 3d 26 } //01 00  bver=&tid=&mt=000000&bname=&ver=&time=-001/-1/-1%20-1:-1:-&upg=&
		$a_01_4 = {62 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 74 69 64 3d 26 6d 74 3d 30 30 30 30 30 30 26 62 6e 61 6d 65 3d 26 76 65 72 3d 26 75 70 67 3d 26 } //01 00  bver=&time=-001/-1/-1%20-1:-1:-&tid=&mt=000000&bname=&ver=&upg=&
		$a_01_5 = {76 65 72 3d 26 62 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 74 69 64 3d 26 6d 74 3d 30 30 30 30 30 30 26 62 6e 61 6d 65 3d 26 75 70 67 3d 26 } //01 00  ver=&bver=&time=-001/-1/-1%20-1:-1:-&tid=&mt=000000&bname=&upg=&
		$a_01_6 = {76 65 72 3d 26 6d 74 3d 30 30 30 30 30 30 26 62 76 65 72 3d 26 74 69 6d 65 3d 2d 30 30 31 2f 2d 31 2f 2d 31 25 32 30 2d 31 3a 2d 31 3a 2d 26 74 69 64 3d 26 62 6e 61 6d 65 3d 26 75 70 67 3d 26 } //01 00  ver=&mt=000000&bver=&time=-001/-1/-1%20-1:-1:-&tid=&bname=&upg=&
		$a_01_7 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai_upgrade_url
		$a_01_8 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  b$sai_upgrade_url
		$a_01_9 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bs$ai_upgrade_url
		$a_01_10 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsa$i_upgrade_url
		$a_01_11 = {62 00 73 00 61 00 69 00 24 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai$_upgrade_url
		$a_01_12 = {62 00 73 00 61 00 69 00 5f 00 75 00 24 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai_u$pgrade_url
		$a_01_13 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 24 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai_up$grade_url
		$a_01_14 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 24 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai_upg$rade_url
		$a_01_15 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai_upgr$ade_url
		$a_01_16 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai_upgra$de_url
		$a_01_17 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 24 00 67 00 72 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  b$sai_up$grade_url
		$a_01_18 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 24 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 75 00 24 00 72 00 6c 00 } //01 00  b$sai_up$gra$de_u$rl
		$a_01_19 = {62 00 24 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 24 00 67 00 72 00 24 00 61 00 24 00 64 00 65 00 5f 00 75 00 24 00 72 00 6c 00 } //01 00  b$sa$i_up$gr$a$de_u$rl
		$a_01_20 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bs$ai_upgr$ade_url
		$a_01_21 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bs$ai_upgra$de_url
		$a_01_22 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 24 00 5f 00 75 00 72 00 6c 00 } //01 00  bs$ai_upgrade$_url
		$a_01_23 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsa$i_upgr$ade_url
		$a_01_24 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsa$i_upgra$de_url
		$a_01_25 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 24 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsa$i_upgrad$e_url
		$a_01_26 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 24 00 5f 00 75 00 72 00 6c 00 } //01 00  bsa$i_upgrade$_url
		$a_01_27 = {62 00 73 00 61 00 69 00 24 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai$_upgr$ade_url
		$a_01_28 = {62 00 73 00 61 00 69 00 24 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 24 00 5f 00 75 00 72 00 6c 00 } //01 00  bsai$_upgrade$_url
		$a_01_29 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 24 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 68 00 24 00 61 00 73 00 68 00 } //01 00  bs$ai_up$gr$ade_h$ash
		$a_01_30 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai_upgrade_hash
		$a_01_31 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  b$sai_upgrade_hash
		$a_01_32 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bs$ai_upgrade_hash
		$a_01_33 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsa$i_upgrade_hash
		$a_01_34 = {62 00 73 00 61 00 69 00 5f 00 24 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai_$upgrade_hash
		$a_01_35 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 24 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai_up$grade_hash
		$a_01_36 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai_upgr$ade_hash
		$a_01_37 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai_upgra$de_hash
		$a_01_38 = {62 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 24 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai_upgrad$e_hash
		$a_01_39 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 24 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  b$sai_upgrade$_hash
		$a_01_40 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 24 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  b$sai_upgrad$e_hash
		$a_01_41 = {62 00 24 00 73 00 61 00 69 00 5f 00 75 00 70 00 67 00 24 00 72 00 61 00 64 00 24 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  b$sai_upg$rad$e_hash
		$a_01_42 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bs$ai_upgr$ade_hash
		$a_01_43 = {62 00 73 00 24 00 61 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bs$ai_upgra$de_hash
		$a_01_44 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsa$i_upgr$ade_hash
		$a_01_45 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 24 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsa$i_upgra$de_hash
		$a_01_46 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 24 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsa$i_upgrad$e_hash
		$a_01_47 = {62 00 73 00 61 00 24 00 69 00 5f 00 75 00 70 00 67 00 72 00 61 00 64 00 65 00 24 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsa$i_upgrade$_hash
		$a_01_48 = {62 00 73 00 61 00 69 00 24 00 5f 00 75 00 24 00 70 00 67 00 72 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai$_u$pgrade_hash
		$a_01_49 = {62 00 73 00 61 00 69 00 24 00 5f 00 75 00 70 00 67 00 72 00 24 00 61 00 64 00 65 00 5f 00 68 00 61 00 73 00 68 00 } //01 00  bsai$_upgr$ade_hash
		$a_01_50 = {62 00 73 00 24 00 61 00 69 00 24 00 5f 00 75 00 70 00 67 00 24 00 72 00 61 00 24 00 64 00 65 00 5f 00 75 00 24 00 72 00 6c 00 } //01 00  bs$ai$_upg$ra$de_u$rl
		$a_00_51 = {62 00 73 00 61 00 69 00 74 00 65 00 73 00 74 00 } //01 00  bsaitest
		$a_00_52 = {62 00 5f 00 73 00 61 00 69 00 5f 00 74 00 65 00 73 00 74 00 } //01 00  b_sai_test
		$a_01_53 = {73 00 61 00 69 00 5f 00 74 00 65 00 73 00 74 00 3d 00 25 00 6c 00 75 00 20 00 28 00 30 00 78 00 25 00 78 00 29 00 } //01 00  sai_test=%lu (0x%x)
		$a_01_54 = {69 00 63 00 6e 00 61 00 6d 00 65 00 7c 00 69 00 63 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 7c 00 74 00 69 00 64 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 6f 00 73 00 7c 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 7c 00 63 00 73 00 63 00 69 00 64 00 7c 00 68 00 64 00 69 00 64 00 } //01 00  icname|icversion|tid|arguments.os|locale|arguments.browser|cscid|hdid
		$a_01_55 = {69 00 63 00 6e 00 61 00 6d 00 65 00 7c 00 69 00 63 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 7c 00 74 00 69 00 64 00 7c 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 6f 00 73 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 7c 00 63 00 73 00 63 00 69 00 64 00 7c 00 68 00 64 00 69 00 64 00 } //01 00  icname|icversion|tid|locale|arguments.os|arguments.browser|cscid|hdid
		$a_01_56 = {69 00 63 00 6e 00 61 00 6d 00 65 00 7c 00 74 00 69 00 64 00 7c 00 69 00 63 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 7c 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 6f 00 73 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 7c 00 63 00 73 00 63 00 69 00 64 00 7c 00 68 00 64 00 69 00 64 00 } //01 00  icname|tid|icversion|locale|arguments.os|arguments.browser|cscid|hdid
		$a_01_57 = {69 00 63 00 6e 00 61 00 6d 00 65 00 7c 00 74 00 69 00 64 00 7c 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 7c 00 69 00 63 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 6f 00 73 00 7c 00 61 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 7c 00 63 00 73 00 63 00 69 00 64 00 7c 00 68 00 64 00 69 00 64 00 } //01 00  icname|tid|locale|icversion|arguments.os|arguments.browser|cscid|hdid
		$a_01_58 = {53 00 41 00 49 00 53 00 61 00 76 00 65 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 28 00 27 00 25 00 73 00 27 00 2c 00 20 00 27 00 25 00 73 00 27 00 29 00 20 00 28 00 77 00 61 00 73 00 20 00 27 00 25 00 73 00 27 00 29 00 } //01 00  SAISaveSetting('%s', '%s') (was '%s')
		$a_01_59 = {56 00 49 00 43 00 50 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 4c 00 69 00 73 00 74 00 } //01 00  VICParameterNameList
		$a_01_60 = {56 00 49 00 43 00 20 00 55 00 70 00 67 00 72 00 61 00 64 00 65 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 65 00 64 00 2c 00 20 00 69 00 67 00 6e 00 6f 00 72 00 65 00 64 00 } //01 00  VIC Upgrade requested, ignored
		$a_01_61 = {53 00 41 00 49 00 53 00 65 00 74 00 48 00 6f 00 74 00 6b 00 65 00 79 00 } //01 00  SAISetHotkey
		$a_01_62 = {56 00 49 00 43 00 20 00 55 00 52 00 4c 00 3a 00 20 00 25 00 73 00 0d 00 0a 00 56 00 49 00 43 00 20 00 50 00 61 00 72 00 61 00 6d 00 73 00 3a 00 } //01 00 
		$a_01_63 = {65 00 72 00 72 00 6f 00 72 00 20 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 20 00 41 00 53 00 41 00 49 00 20 00 73 00 69 00 67 00 6e 00 61 00 61 00 74 00 75 00 72 00 65 00 3a 00 20 00 25 00 73 00 } //01 00  error reading ASAI signaature: %s
		$a_01_64 = {4f 00 6e 00 53 00 41 00 49 00 56 00 65 00 72 00 69 00 66 00 79 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 28 00 29 00 3a 00 } //01 00  OnSAIVerifyInstall():
		$a_03_65 = {25 00 64 00 2f 00 25 00 64 00 2f 00 25 00 30 00 34 00 64 00 20 00 25 00 64 00 3a 00 25 00 30 00 32 00 64 00 3a 00 25 00 30 00 32 00 64 00 20 00 25 00 90 02 02 73 00 90 00 } //01 00 
		$a_03_66 = {25 00 30 00 34 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 2e 00 25 00 30 00 33 00 75 00 2e 00 25 00 90 02 02 75 00 90 00 } //01 00 
		$a_00_67 = {74 00 65 00 2e 00 61 00 73 00 70 00 78 00 3f 00 76 00 65 00 72 00 3d 00 26 00 72 00 6e 00 64 00 3d 00 } //01 00  te.aspx?ver=&rnd=
		$a_02_68 = {74 00 65 00 2e 00 61 00 73 00 70 00 78 00 3f 00 72 00 6e 00 64 00 3d 00 90 02 06 26 00 76 00 65 00 72 00 3d 00 90 00 } //01 00 
		$a_02_69 = {74 00 65 00 2e 00 61 00 73 00 70 00 78 00 3f 00 61 00 78 00 30 00 3d 00 90 01 0d 26 00 72 00 6e 00 64 00 3d 00 90 01 06 26 00 76 00 65 00 72 00 3d 00 90 00 } //01 00 
		$a_01_70 = {70 00 6c 00 61 00 74 00 72 00 69 00 75 00 6d 00 2e 00 63 00 6f 00 6d 00 } //01 00  platrium.com
		$a_01_71 = {61 00 70 00 70 00 62 00 75 00 6e 00 64 00 6c 00 65 00 72 00 2e 00 6e 00 65 00 74 00 } //01 00  appbundler.net
		$a_01_72 = {61 00 70 00 70 00 62 00 75 00 6e 00 64 00 6c 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //01 00  appbundler.com
		$a_01_73 = {70 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 63 00 6f 00 72 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  pinballcorp.com
		$a_01_74 = {66 00 72 00 65 00 65 00 6c 00 61 00 6e 00 64 00 6d 00 65 00 64 00 69 00 61 00 2e 00 63 00 6f 00 6d 00 } //01 00  freelandmedia.com
		$a_01_75 = {7a 00 61 00 6e 00 67 00 6f 00 2e 00 63 00 6f 00 6d 00 } //01 00  zango.com
		$a_01_76 = {73 00 65 00 65 00 6b 00 6d 00 6f 00 2e 00 63 00 6f 00 6d 00 } //01 00  seekmo.com
		$a_01_77 = {6c 00 68 00 6f 00 6f 00 74 00 2e 00 63 00 6f 00 6d 00 } //00 00  lhoot.com
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_44{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5f 73 61 5c 42 69 6e 5c 52 65 6c 65 61 73 65 5c 53 65 74 75 70 2e 70 64 62 } //01 00  source_sa\Bin\Release\Setup.pdb
		$a_01_1 = {53 6d 61 72 74 20 53 68 6f 70 70 65 72 } //01 00  Smart Shopper
		$a_01_2 = {5a 61 6e 67 6f } //01 00  Zango
		$a_01_3 = {61 70 70 62 75 6e 64 6c 65 72 2e 63 6f 6d } //00 00  appbundler.com
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_45{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6e 00 74 00 6e 00 74 00 43 00 6e 00 74 00 72 00 2e 00 43 00 6e 00 74 00 6e 00 74 00 44 00 69 00 73 00 70 00 } //01 00  CntntCntr.CntntDisp
		$a_01_1 = {68 74 74 70 3a 2f 2f 68 6f 74 62 61 72 2e 63 6f 6d } //01 00  http://hotbar.com
		$a_01_2 = {6a 61 76 61 73 63 72 69 70 74 3a 77 69 6e 64 6f 77 2e 6f 70 65 6e } //00 00  javascript:window.open
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_46{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,29 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 62 48 6f 73 74 4f 45 50 61 74 68 } //0a 00  HbHostOEPath
		$a_01_1 = {4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 20 42 72 6f 77 73 65 72 20 43 6c 61 73 73 } //0a 00  Outlook Express Browser Class
		$a_01_2 = {68 62 68 6f 73 74 6f 6c 2e 64 6c 6c } //0a 00  hbhostol.dll
		$a_01_3 = {48 62 48 6f 73 74 4f 45 2e 44 4c 4c } //01 00  HbHostOE.DLL
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f 5c 5a 61 6e 67 6f 5c } //01 00  Software\Zango\Zango\
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 53 65 65 6b 6d 6f 5c 53 65 65 6b 6d 6f 5c } //00 00  Software\Seekmo\Seekmo\
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_47{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 61 6e 67 6f 53 41 48 6f 6f 6b 2e 64 6c 6c } //01 00  ZangoSAHook.dll
		$a_01_1 = {73 65 65 6b 6d 6f 73 61 7c 7a 61 6e 67 6f 73 61 7c 73 62 75 73 61 7c 68 6f 74 62 61 72 73 61 } //01 00  seekmosa|zangosa|sbusa|hotbarsa
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f } //01 00  Software\Zango
		$a_01_3 = {31 38 30 73 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //fc ff  180search Assistant
		$a_01_4 = {65 00 41 00 63 00 63 00 65 00 6c 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 72 00 70 00 } //00 00  eAcceleration Corp
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_48{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 62 54 6f 6f 6c 62 61 72 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 54 56 52 65 6d 6f 74 65 45 78 65 63 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {43 48 62 54 6f 6f 6c 62 61 72 43 74 6c 3a 3a 4f 6e 41 64 53 65 72 76 65 72 52 65 74 75 72 6e } //00 00  CHbToolbarCtl::OnAdServerReturn
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_49{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //01 00  GetLastActivePopup
		$a_01_1 = {42 00 36 00 30 00 42 00 36 00 36 00 30 00 33 00 2d 00 41 00 43 00 43 00 46 00 2d 00 34 00 63 00 65 00 39 00 2d 00 42 00 46 00 35 00 34 00 2d 00 44 00 35 00 39 00 44 00 45 00 45 00 30 00 45 00 41 00 41 00 43 00 36 00 } //01 00  B60B6603-ACCF-4ce9-BF54-D59DEE0EAAC6
		$a_01_2 = {68 74 74 70 3a 2f 2f 6f 70 65 6e 2f 3f 75 72 6c 3d } //01 00  http://open/?url=
		$a_01_3 = {69 74 73 2e 6e 6f 74 2e 6f 6b } //01 00  its.not.ok
		$a_01_4 = {5c 68 6f 74 62 61 72 5f 72 65 6c 65 61 73 65 5c } //00 00  \hotbar_release\
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_50{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6c 6c 73 2e 68 6f 74 62 61 72 2e 63 6f 6d } //01 00  installs.hotbar.com
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f 5c 5a 61 6e 67 6f 5c } //01 00  Software\Zango\Zango\
		$a_01_2 = {7a 61 6e 67 6f 2e 63 6f 6d } //01 00  zango.com
		$a_01_3 = {48 42 49 6e 73 74 49 45 2e 44 4c 4c } //01 00  HBInstIE.DLL
		$a_01_4 = {69 6e 73 74 61 6c 6c 73 2e 7a 61 6e 67 6f 2e 63 6f 6d } //01 00  installs.zango.com
		$a_01_5 = {2e 3f 41 55 49 48 62 49 6e 73 74 4f 62 6a 40 40 } //01 00  .?AUIHbInstObj@@
		$a_01_6 = {49 00 6e 00 73 00 74 00 49 00 45 00 2e 00 48 00 62 00 49 00 6e 00 73 00 74 00 4f 00 62 00 6a 00 } //00 00  InstIE.HbInstObj
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_51{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,6c 00 6c 00 07 00 00 64 00 "
		
	strings :
		$a_01_0 = {00 00 53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 5c 48 6f 74 62 61 72 5c 00 53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 5c 00 00 00 00 } //02 00 
		$a_01_1 = {48 6f 74 62 61 72 5c 62 69 6e } //02 00  Hotbar\bin
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 48 6f 74 62 61 72 } //02 00  Software\Hotbar
		$a_01_3 = {68 6f 74 62 61 72 2e 63 6f 6d } //01 00  hotbar.com
		$a_01_4 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_01_6 = {68 62 69 6e 73 74 } //00 00  hbinst
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_52{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 2e 00 76 00 62 00 70 00 } //01 00  Pinball.vbp
		$a_01_1 = {6f 00 72 00 69 00 67 00 69 00 6e 00 2d 00 69 00 63 00 73 00 2e 00 68 00 6f 00 74 00 62 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 } //01 00  origin-ics.hotbar.com
		$a_01_2 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 3d 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 68 00 6f 00 74 00 62 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 } //01 00  installerDomain=config.hotbar.com
		$a_01_3 = {26 00 76 00 2e 00 6d 00 65 00 74 00 68 00 6f 00 64 00 3d 00 70 00 6f 00 70 00 6f 00 76 00 65 00 72 00 } //00 00  &v.method=popover
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_53{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,0b 00 01 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //01 00  Pinball Corporation
		$a_01_1 = {6e 70 63 6c 6e 74 61 78 5f 48 42 4c 69 74 65 53 41 2e 64 6c 6c } //01 00  npclntax_HBLiteSA.dll
		$a_01_2 = {53 4f 41 50 41 63 74 69 6f 6e 57 65 61 74 68 65 72 } //01 00  SOAPActionWeather
		$a_01_3 = {5c 57 65 53 6b 69 6e 2e 70 64 62 } //01 00  \WeSkin.pdb
		$a_01_4 = {53 00 65 00 65 00 6b 00 6d 00 6f 00 20 00 50 00 72 00 69 00 76 00 61 00 63 00 79 00 20 00 4d 00 6f 00 64 00 65 00 } //01 00  Seekmo Privacy Mode
		$a_01_5 = {53 65 74 75 70 2e 64 6c 6c 00 56 65 72 69 66 79 53 69 67 6e 61 74 75 72 65 } //01 00 
		$a_01_6 = {47 65 74 4e 43 4d 59 42 46 69 6c 65 56 65 72 73 69 6f 6e 00 47 65 74 4e 43 4d 59 42 46 69 6c 65 56 65 72 73 69 6f 6e 4d 61 6a 6f 72 } //01 00  敇乴䵃䉙楆敬敖獲潩n敇乴䵃䉙楆敬敖獲潩䵮橡牯
		$a_01_7 = {47 65 74 45 6c 65 76 61 74 69 6f 6e 54 79 70 65 00 49 73 45 6c 65 76 61 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_54{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 61 64 20 69 73 20 66 72 6f 6d 20 48 6f 74 62 61 72 20 61 6e 64 20 6e 6f 74 20 66 72 6f 6d 20 74 68 65 20 73 69 74 65 20 76 69 73 69 74 65 64 20 2d 20 63 6c 69 63 6b 20 68 65 72 65 20 66 6f 72 20 6d 6f 72 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e } //01 00  This ad is from Hotbar and not from the site visited - click here for more information.
		$a_01_1 = {68 74 74 70 3a 2f 2f 63 74 73 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f } //01 00  http://cts.hotbar.com/
		$a_01_2 = {68 74 74 70 3a 2f 2f 70 69 6e 67 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d } //01 00  http://ping.180solutions.com
		$a_01_3 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f } //01 00  http://downloads.180solutions.com/
		$a_01_4 = {68 74 74 70 3a 2f 2f 62 69 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f } //01 00  http://bis.180solutions.com/
		$a_01_5 = {6e 6f 77 68 65 72 65 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d } //01 00  nowhere.180solutions.com
		$a_01_6 = {74 76 2e 68 6f 74 62 61 72 2e 63 6f 6d 2f } //01 00  tv.hotbar.com/
		$a_01_7 = {75 70 6c 6f 61 64 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d } //01 00  uploads.180solutions.com
		$a_01_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 6f 74 62 61 72 2e 63 6f 6d } //05 00  http://www.hotbar.com
		$a_01_9 = {48 00 6f 00 74 00 42 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 2c 00 20 00 49 00 6e 00 63 00 2e 00 } //00 00  HotBar.com, Inc.
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_Hotbar_55{
	meta:
		description = "Adware:Win32/Hotbar,SIGNATURE_TYPE_PEHSTR,10 00 10 00 0d 00 00 05 00 "
		
	strings :
		$a_01_0 = {25 73 20 73 65 61 72 63 68 20 61 73 73 69 73 74 61 6e 74 } //05 00  %s search assistant
		$a_01_1 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 50 40 73 73 57 25 72 64 00 } //01 00 
		$a_01_2 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 53 69 67 6e 40 74 75 72 33 00 } //01 00  湏㡥協汯瑵潩獮楓湧瑀牵3
		$a_01_3 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 43 6f 6e 74 40 69 6e 33 72 4e 40 6d 65 00 } //01 00  湏㡥協汯瑵潩獮潃瑮楀㍮乲浀e
		$a_01_4 = {42 6b 75 70 5f 61 64 5f 75 72 6c } //01 00  Bkup_ad_url
		$a_01_5 = {73 6f 66 74 77 61 72 65 5c 7a 61 6e 67 6f } //01 00  software\zango
		$a_01_6 = {77 6d 5f 73 68 6f 77 5f 61 64 20 72 65 71 75 65 73 74 20 72 65 63 65 69 76 65 64 00 } //01 00  海獟潨彷摡爠煥敵瑳爠捥楥敶d
		$a_01_7 = {70 6f 70 70 69 6e 67 20 61 20 47 41 44 20 61 64 20 2d 20 61 64 20 69 64 20 28 25 73 29 20 20 6b 65 79 77 6f 72 64 20 69 64 20 28 25 73 29 } //01 00  popping a GAD ad - ad id (%s)  keyword id (%s)
		$a_01_8 = {61 74 74 65 6d 70 74 20 74 6f 20 73 68 6f 77 20 61 6e 20 61 64 20 74 69 6d 65 64 20 6f 75 74 00 } //01 00 
		$a_01_9 = {63 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 61 64 73 2e 61 73 70 78 00 } //01 00 
		$a_01_10 = {61 64 5f 68 69 73 74 6f 72 79 5f 63 6f 75 6e 74 00 } //01 00 
		$a_01_11 = {64 6f 77 6e 6c 6f 61 64 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f } //01 00  downloads.180solutions.com/
		$a_01_12 = {31 38 30 67 65 74 65 78 65 6e 61 6d 65 00 } //00 00  㠱朰瑥硥湥浡e
	condition:
		any of ($a_*)
 
}