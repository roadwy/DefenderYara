
rule TrojanClicker_Win32_Hatigh_B{
	meta:
		description = "TrojanClicker:Win32/Hatigh.B,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 Software\Microsoft\Internet Explorer\Main
		$a_01_1 = {37 73 65 61 72 63 68 2e 63 6f 6d 2f 73 63 72 69 70 74 73 2f 73 65 63 75 72 69 74 79 2f 76 61 6c 69 64 61 74 65 2e 61 73 70 } //1 7search.com/scripts/security/validate.asp
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4e 65 77 20 57 69 6e 64 6f 77 73 } //1 Software\Microsoft\Internet Explorer\New Windows
		$a_01_3 = {67 72 64 73 66 73 64 2e 62 61 74 } //1 grdsfsd.bat
		$a_01_4 = {76 61 6c 75 65 3d 6e 6f 5f 73 70 79 77 61 72 65 } //1 value=no_spyware
		$a_01_5 = {68 74 74 70 3a 2f 2f 36 36 2e 31 39 39 2e 31 37 39 2e 38 2f 73 65 61 72 63 68 2e 70 68 70 } //1 http://66.199.179.8/search.php
		$a_01_6 = {36 36 2e 32 35 30 2e 37 34 2e 31 35 32 2f 6b 77 5f 69 6d 67 2f 69 6d 67 5f 67 65 6e 2e 70 68 70 } //1 66.250.74.152/kw_img/img_gen.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}