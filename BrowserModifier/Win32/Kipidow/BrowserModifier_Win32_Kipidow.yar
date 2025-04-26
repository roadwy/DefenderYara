
rule BrowserModifier_Win32_Kipidow{
	meta:
		description = "BrowserModifier:Win32/Kipidow,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 68 00 61 00 6f 00 2e 00 33 00 36 00 30 00 2e 00 63 00 6e 00 2f 00 3f 00 73 00 72 00 63 00 3d 00 6c 00 6d 00 26 00 6c 00 73 00 3d 00 6e 00 34 00 36 00 36 00 63 00 33 00 64 00 66 00 34 00 39 00 66 00 } //1 http://hao.360.cn/?src=lm&ls=n466c3df49f
		$a_01_1 = {4b 00 50 00 44 00 6f 00 77 00 6e 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 } //1 KPDownCaption
		$a_01_2 = {4b 00 50 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 52 00 75 00 6e 00 } //1 KPDesktopRun
		$a_01_3 = {6b 00 70 00 64 00 6f 00 77 00 6e 00 2e 00 69 00 6e 00 69 00 } //1 kpdown.ini
		$a_01_4 = {2f 2f 6b 68 69 74 2e 63 6e 2f 78 6c 64 6c 2e 7a 69 70 } //1 //khit.cn/xldl.zip
		$a_01_5 = {62 69 6e 5f 6b 70 5c 4b 50 44 6f 77 6e 5c } //1 bin_kp\KPDown\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}