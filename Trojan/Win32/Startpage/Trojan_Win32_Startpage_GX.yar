
rule Trojan_Win32_Startpage_GX{
	meta:
		description = "Trojan:Win32/Startpage.GX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d 26 74 6e 3d 79 78 64 6f 77 6e 63 6e 26 69 65 3d 75 74 66 2d 38 } //1 ={searchTerms}&tn=yxdowncn&ie=utf-8
		$a_01_1 = {62 61 69 64 75 2c 68 61 6f 31 32 33 2c 71 71 35 2c 67 6f 32 30 30 30 2c 31 31 38 38 2c 31 38 35 62 } //1 baidu,hao123,qq5,go2000,1188,185b
		$a_01_2 = {7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d } //1 {871C5380-42A0-1069-A2EA-08002B30309D}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}