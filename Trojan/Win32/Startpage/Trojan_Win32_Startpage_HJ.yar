
rule Trojan_Win32_Startpage_HJ{
	meta:
		description = "Trojan:Win32/Startpage.HJ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 00 00 ff ff ff ff 0a 00 00 00 53 74 61 72 74 20 50 61 67 65 } //01 00 
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c } //01 00  \Microsoft\Internet Explorer\Quick Launch\
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 64 76 61 6e 63 65 64 20 49 4e 46 20 53 65 74 75 70 } //01 00  SOFTWARE\Microsoft\Advanced INF Setup
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d 2f 73 3f 77 64 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d 26 74 6e 3d 79 78 64 6f 77 6e 63 6e 26 69 65 3d 75 74 66 2d 38 } //01 00  http://www.baidu.com/s?wd={searchTerms}&tn=yxdowncn&ie=utf-8
		$a_01_4 = {69 65 5c 00 ff ff ff ff 0c 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}