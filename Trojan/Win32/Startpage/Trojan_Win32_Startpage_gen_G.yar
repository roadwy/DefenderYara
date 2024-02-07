
rule Trojan_Win32_Startpage_gen_G{
	meta:
		description = "Trojan:Win32/Startpage.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,4f 00 4b 00 10 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 20 50 61 67 65 } //0a 00  Start Page
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //0a 00  Software\Microsoft\Internet Explorer\Main
		$a_01_2 = {25 73 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //0a 00  %s\drivers\etc\hosts
		$a_01_3 = {77 65 63 78 67 33 32 2e 64 6c 6c } //0a 00  wecxg32.dll
		$a_01_4 = {7b 34 32 33 34 66 37 30 30 2d 63 62 61 33 2d 34 30 37 31 2d 62 32 35 31 2d 34 37 63 62 38 39 34 32 34 34 63 64 7d } //0a 00  {4234f700-cba3-4071-b251-47cb894244cd}
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //0a 00  InternetOpenUrlA
		$a_00_6 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //01 00  RegSetValueExA
		$a_01_7 = {7a 78 6d 73 6e 2e 64 6c 6c } //01 00  zxmsn.dll
		$a_01_8 = {67 75 70 64 2e 64 6c 6c } //01 00  gupd.dll
		$a_01_9 = {63 69 64 70 6f 71 33 32 2e 64 6c 6c } //01 00  cidpoq32.dll
		$a_01_10 = {63 69 64 66 74 2e 64 6c 6c } //01 00  cidft.dll
		$a_01_11 = {73 64 66 75 70 2e 64 6c 6c } //01 00  sdfup.dll
		$a_01_12 = {78 63 77 65 72 33 32 2e 64 6c 6c } //01 00  xcwer32.dll
		$a_01_13 = {69 63 76 62 72 2e 64 6c 6c } //01 00  icvbr.dll
		$a_01_14 = {69 63 71 72 74 2e 64 6c 6c } //01 00  icqrt.dll
		$a_01_15 = {69 63 6e 66 65 2e 64 6c 6c } //00 00  icnfe.dll
	condition:
		any of ($a_*)
 
}