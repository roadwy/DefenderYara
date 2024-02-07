
rule Trojan_Win32_Adclicker_AJ{
	meta:
		description = "Trojan:Win32/Adclicker.AJ,SIGNATURE_TYPE_PEHSTR_EXT,50 00 4b 00 20 00 00 32 00 "
		
	strings :
		$a_00_0 = {38 36 41 34 34 45 46 37 2d 37 38 46 43 2d 34 65 31 38 2d 41 35 36 34 2d 42 31 38 46 38 30 36 46 37 46 35 36 } //0a 00  86A44EF7-78FC-4e18-A564-B18F806F7F56
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //0a 00  InternetReadFile
		$a_00_2 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_00_3 = {6d 79 2e 62 65 67 75 6e 2e 72 75 } //01 00  my.begun.ru
		$a_00_4 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 64 73 65 6e 73 65 2f } //01 00  google.com/adsense/
		$a_00_5 = {70 72 6f 6d 6f 66 6f 72 75 6d 2e 72 75 } //01 00  promoforum.ru
		$a_00_6 = {73 65 6f 63 68 61 73 65 2e 63 6f 6d } //01 00  seochase.com
		$a_00_7 = {6d 61 73 74 65 72 74 61 6c 6b 2e 72 75 } //01 00  mastertalk.ru
		$a_00_8 = {66 6f 72 75 6d 2e 73 65 61 72 63 68 65 6e 67 69 6e 65 73 2e 72 75 } //01 00  forum.searchengines.ru
		$a_00_9 = {73 65 61 72 63 68 65 6e 67 69 6e 65 73 2e 72 75 } //01 00  searchengines.ru
		$a_00_10 = {61 72 6d 61 64 61 62 6f 61 72 64 2e 63 6f 6d } //01 00  armadaboard.com
		$a_00_11 = {75 6d 61 78 66 6f 72 75 6d 2e 63 6f 6d } //01 00  umaxforum.com
		$a_00_12 = {63 72 75 74 6f 70 2e 6e 75 } //01 00  crutop.nu
		$a_00_13 = {63 72 75 74 6f 70 2e 63 6f 6d } //01 00  crutop.com
		$a_00_14 = {6d 61 73 74 65 72 2d 78 2e 63 6f 6d } //01 00  master-x.com
		$a_00_15 = {75 6d 61 78 6c 6f 67 69 6e 2e 63 6f 6d } //01 00  umaxlogin.com
		$a_00_16 = {72 75 73 61 77 6d 2e 63 6f 6d } //01 00  rusawm.com
		$a_00_17 = {67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 2e 63 6f 6d } //01 00  gofuckyourself.com
		$a_00_18 = {6f 70 72 61 6e 6f 2e 63 6f 6d } //01 00  oprano.com
		$a_00_19 = {67 66 79 62 6f 61 72 64 2e 63 6f 6d } //01 00  gfyboard.com
		$a_00_20 = {67 66 79 2e 63 6f 6d } //01 00  gfy.com
		$a_00_21 = {61 64 75 6c 74 77 65 62 6d 61 73 74 65 72 69 6e 66 6f 2e 63 6f 6d } //01 00  adultwebmasterinfo.com
		$a_00_22 = {78 62 69 7a 2e 63 6f 6d } //01 00  xbiz.com
		$a_00_23 = {62 6f 61 72 64 73 2e 78 62 69 7a 2e 63 6f 6d } //01 00  boards.xbiz.com
		$a_00_24 = {6e 61 73 74 72 61 66 6f 72 75 6d 2e 63 6f 6d } //01 00  nastraforum.com
		$a_00_25 = {77 65 62 68 6f 73 74 69 6e 67 74 61 6c 6b 2e 63 6f 6d } //01 00  webhostingtalk.com
		$a_00_26 = {73 65 61 72 63 68 65 6e 67 69 6e 65 66 6f 72 75 6d 73 2e 63 6f 6d } //01 00  searchengineforums.com
		$a_00_27 = {62 65 6e 65 64 65 6c 6d 61 6e 2e 6f 72 67 } //01 00  benedelman.org
		$a_00_28 = {77 65 62 6d 61 73 74 65 72 77 6f 72 6c 64 2e 63 6f 6d } //01 00  webmasterworld.com
		$a_00_29 = {61 73 6b 64 61 6d 61 67 65 2e 63 6f 6d } //01 00  askdamage.com
		$a_00_30 = {6e 61 6d 65 70 72 6f 73 2e 63 6f 6d } //01 00  namepros.com
		$a_00_31 = {63 61 73 74 6c 65 63 6f 70 73 2e 63 6f 6d } //00 00  castlecops.com
	condition:
		any of ($a_*)
 
}