
rule BrowserModifier_Win32_Istbar_C{
	meta:
		description = "BrowserModifier:Win32/Istbar.C,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 53 54 61 63 74 69 76 65 78 2e 44 4c 4c } //10 ISTactivex.DLL
		$a_00_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 6c 00 6f 00 63 00 6b 00 } //3 download_lock
		$a_00_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 6b 00 65 00 79 00 } //3 download_key
		$a_00_3 = {61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 69 00 64 00 } //1 account_id
		$a_00_4 = {43 00 4c 00 44 00 45 00 53 00 43 00 } //2 CLDESC
		$a_00_5 = {43 00 4c 00 4e 00 41 00 4d 00 45 00 } //2 CLNAME
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=16
 
}
rule BrowserModifier_Win32_Istbar_C_2{
	meta:
		description = "BrowserModifier:Win32/Istbar.C,SIGNATURE_TYPE_PEHSTR,0a 00 08 00 14 00 00 "
		
	strings :
		$a_01_0 = {69 6e 73 74 61 6c 6c 2e 78 78 78 74 6f 6f 6c 62 61 72 2e 63 6f 6d } //2 install.xxxtoolbar.com
		$a_01_1 = {77 77 77 2e 79 73 62 77 65 62 2e 63 6f 6d } //2 www.ysbweb.com
		$a_01_2 = {77 77 77 2e 73 6c 6f 74 63 68 2e 63 6f 6d } //2 www.slotch.com
		$a_01_3 = {63 64 6e 2e 63 6c 69 6d 61 78 62 75 63 6b 73 2e 63 6f 6d } //2 cdn.climaxbucks.com
		$a_01_4 = {77 77 77 2e 73 70 32 61 64 6d 69 6e 2e 62 69 7a } //2 www.sp2admin.biz
		$a_01_5 = {79 73 62 5f 6d 33 } //2 ysb_m3
		$a_01_6 = {79 73 62 5f 6d 70 33 } //2 ysb_mp3
		$a_01_7 = {79 73 62 5f 63 68 65 61 74 } //2 ysb_cheat
		$a_01_8 = {79 73 62 5f 64 65 6d 6f } //2 ysb_demo
		$a_01_9 = {25 73 3f 63 66 67 3d 25 73 26 61 63 63 6f 75 6e 74 5f 69 64 3d 25 73 } //2 %s?cfg=%s&account_id=%s
		$a_01_10 = {4b 57 61 65 79 67 35 4b 6f 37 61 6f 6a 63 39 } //2 KWaeyg5Ko7aojc9
		$a_01_11 = {25 73 3f 61 69 64 3d 25 69 26 63 66 67 3d 25 73 26 76 6b 65 79 3d 25 73 } //2 %s?aid=%i&cfg=%s&vkey=%s
		$a_01_12 = {2f 50 43 3d 43 50 2e 49 53 54 20 } //2 /PC=CP.IST 
		$a_01_13 = {2f 61 69 64 3a } //1 /aid:
		$a_01_14 = {2f 63 66 67 3a } //1 /cfg:
		$a_01_15 = {53 6f 66 74 77 61 72 65 5c 49 53 54 } //1 Software\IST
		$a_01_16 = {69 73 74 62 61 72 } //1 istbar
		$a_01_17 = {42 61 6e 64 52 65 73 74 } //1 BandRest
		$a_01_18 = {25 73 20 2f 73 75 62 3a 25 73 } //1 %s /sub:%s
		$a_01_19 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=8
 
}