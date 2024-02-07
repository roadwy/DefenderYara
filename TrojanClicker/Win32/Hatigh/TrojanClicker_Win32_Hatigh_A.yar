
rule TrojanClicker_Win32_Hatigh_A{
	meta:
		description = "TrojanClicker:Win32/Hatigh.A,SIGNATURE_TYPE_PEHSTR,19 00 14 00 1d 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_1 = {37 73 65 61 72 63 68 2e 63 6f 6d 2f 73 63 72 69 70 74 73 2f 73 65 63 75 72 69 74 79 2f 76 61 6c 69 64 61 74 65 2e 61 73 70 } //01 00  7search.com/scripts/security/validate.asp
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 } //01 00  Software\Microsoft\Internet Explorer\New Windows
		$a_01_3 = {67 72 64 73 66 73 64 2e 62 61 74 } //01 00  grdsfsd.bat
		$a_01_4 = {76 61 6c 75 65 3d 6e 6f 5f 73 70 79 77 61 72 65 } //02 00  value=no_spyware
		$a_01_5 = {68 74 74 70 3a 2f 2f 36 36 2e 31 39 39 2e 31 37 39 2e 38 2f 73 65 61 72 63 68 2e 70 68 70 } //02 00  http://66.199.179.8/search.php
		$a_01_6 = {36 36 2e 32 35 30 2e 37 34 2e 31 35 32 2f 6b 77 5f 69 6d 67 2f 69 6d 67 5f 67 65 6e 2e 70 68 70 } //01 00  66.250.74.152/kw_img/img_gen.php
		$a_01_7 = {3a 24 3a 2a 3a 31 3a 3a 3a 42 3a 49 3a 54 3a 5a 3a 60 3a 6a 3a 70 3a 76 3a } //01 00  :$:*:1:::B:I:T:Z:`:j:p:v:
		$a_01_8 = {68 74 74 70 3a 2f 2f 74 72 69 70 62 6f 72 6e 2e 6f 72 67 2f 72 64 2f 72 65 70 32 2e 70 68 70 3f 65 72 5b 30 5d 3d 35 2e 31 2d } //01 00  http://tripborn.org/rd/rep2.php?er[0]=5.1-
		$a_01_9 = {68 74 74 70 3a 2f 2f 66 69 72 73 74 77 6f 6c 66 2e 6f 72 67 2f 72 64 2f 72 65 70 2e 70 68 70 3f 65 72 5b 30 5d 3d 35 2e 31 2d } //01 00  http://firstwolf.org/rd/rep.php?er[0]=5.1-
		$a_01_10 = {69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 67 6c 32 33 34 73 68 } //01 00  if exist %1 goto gl234sh
		$a_01_11 = {50 6f 70 75 70 4d 67 72 } //01 00  PopupMgr
		$a_01_12 = {53 75 75 72 63 68 } //01 00  Suurch
		$a_01_13 = {66 69 6e 64 6e 73 65 65 6b } //01 00  findnseek
		$a_01_14 = {73 68 6f 70 7a 69 6c } //01 00  shopzil
		$a_01_15 = {77 77 77 2e 73 75 75 72 63 68 2e 63 6f 6d } //01 00  www.suurch.com
		$a_01_16 = {74 65 73 74 6f 76 61 79 61 20 68 72 65 6e } //01 00  testovaya hren
		$a_01_17 = {66 72 61 75 64 } //01 00  fraud
		$a_01_18 = {4e 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //01 00  NookupPrivilegeValueA
		$a_01_19 = {51 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //01 00  QpenProcessToken
		$a_01_20 = {54 65 67 43 6c 6f 73 65 4b 65 79 } //01 00  TegCloseKey
		$a_01_21 = {54 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //01 00  TegSetValueExA
		$a_01_22 = {4a 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //01 00  JttpSendRequestA
		$a_01_23 = {4a 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //01 00  JttpOpenRequestA
		$a_01_24 = {57 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  WRLDownloadToFileA
		$a_01_25 = {55 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  UhellExecuteA
		$a_01_26 = {63 68 65 61 74 } //01 00  cheat
		$a_01_27 = {76 69 6d 67 2e 70 68 70 3f } //01 00  vimg.php?
		$a_01_28 = {42 00 43 00 4d 00 53 00 56 00 43 00 52 00 54 00 2e 00 44 00 4c 00 4c 00 } //00 00  BCMSVCRT.DLL
	condition:
		any of ($a_*)
 
}