
rule BrowserModifier_Win32_CashOn{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 72 65 76 69 6f 75 73 5f 75 70 64 61 74 65 5f 65 78 65 } //2 previous_update_exe
		$a_01_1 = {43 61 73 68 4f 6e 5c 62 69 6e 00 00 2a 2e 65 78 65 00 00 00 55 50 44 41 54 45 52 00 45 6e 61 62 6c 65 20 42 72 6f 77 73 65 72 20 45 78 74 65 6e 73 69 6f 6e 73 } //4
		$a_01_2 = {6e 63 73 65 72 76 2a 2e 65 78 65 } //2 ncserv*.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2) >=8
 
}
rule BrowserModifier_Win32_CashOn_2{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 43 61 73 68 4f 6e } //1 TCashOn
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 61 73 68 4f 6e 5c 64 61 74 61 5c 70 6f 70 75 70 2e 64 61 74 } //2 C:\Program Files\CashOn\data\popup.dat
		$a_01_2 = {23 63 61 73 68 6f 6e 5f 72 74 } //3 #cashon_rt
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 43 61 73 68 4f 6e 5c } //2 SOFTWARE\CashOn\
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 2e 70 68 70 } //3 http://www.cashon.co.kr/search/search.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3) >=8
 
}
rule BrowserModifier_Win32_CashOn_3{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 50 72 6f 6a 65 63 74 5c 50 72 65 73 73 5c 70 72 65 6d 69 65 72 65 2e 6f 72 2e 6b 72 5c 53 6f 75 72 63 65 5c 50 53 43 49 6e 66 6f 2e 64 6c 6c 5f 32 30 } //4 D:\Project\Press\premiere.or.kr\Source\PSCInfo.dll_20
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 6d 61 72 74 2e 6c 69 6e 6b 70 72 69 63 65 2e 63 6f 6d 2f 73 65 6d 2f 6f 76 65 72 74 75 72 65 5f 73 70 6f 6e 73 6f 72 5f 73 65 61 72 63 68 2e 70 68 70 3f 6d 61 78 63 6e 74 3d 26 6a 73 3d 32 26 74 79 70 65 3d } //3 http://smart.linkprice.com/sem/overture_sponsor_search.php?maxcnt=&js=2&type=
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}
rule BrowserModifier_Win32_CashOn_4{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 73 68 6f 6e 75 70 64 61 74 65 } //1 Cashonupdate
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 2f 61 70 70 2f 61 70 70 2e 70 68 70 3f 75 72 6c 3d } //2 http://www.cashon.co.kr/app/app.php?url=
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 61 73 68 4f 6e 5c } //2 SOFTWARE\CashOn\
		$a_01_3 = {73 63 72 69 70 74 2e 73 68 6f 70 2d 67 75 69 64 65 2e 63 6f 2e 6b 72 } //2 script.shop-guide.co.kr
		$a_01_4 = {44 69 73 70 61 74 63 68 20 69 6e 74 65 72 66 61 63 65 20 66 6f 72 20 63 61 73 68 62 68 6f 20 4f 62 6a 65 63 74 57 } //2 Dispatch interface for cashbho ObjectW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}
rule BrowserModifier_Win32_CashOn_5{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 43 61 73 68 4f 6e 5c } //2 SOFTWARE\CashOn\
		$a_01_1 = {62 68 6f 5f 44 61 74 65 } //1 bho_Date
		$a_01_2 = {55 70 64 61 74 65 65 78 65 5f 44 61 74 65 } //1 Updateexe_Date
		$a_01_3 = {7b 30 31 45 30 34 35 38 31 2d 34 45 45 45 2d 31 31 44 30 2d 42 46 45 39 2d 30 30 41 41 30 30 35 42 34 33 38 33 7d } //2 {01E04581-4EEE-11D0-BFE9-00AA005B4383}
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 2f 61 70 70 2f 69 6e 73 74 61 6c 6c 2e 70 68 70 3f } //2 http://www.cashon.co.kr/app/install.php?
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 61 73 68 6f 6e 5c 62 69 6e 5c } //2 C:\Program Files\Cashon\bin\
		$a_01_6 = {43 61 73 68 6f 6e 4d 65 64 69 61 48 6f 6f 6e } //2 CashonMediaHoon
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=8
 
}
rule BrowserModifier_Win32_CashOn_6{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 44 72 69 76 65 72 20 66 6f 72 20 43 61 73 68 6f 6e 74 6f 6f 6c } //2 Windows Driver for Cashontool
		$a_01_1 = {63 61 73 68 6f 6e 62 68 6f } //2 cashonbho
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 61 73 68 4f 6e 5c } //2 SOFTWARE\CashOn\
		$a_01_3 = {43 61 73 68 4f 6e 5c 62 69 6e 5c 4e } //2 CashOn\bin\N
		$a_01_4 = {7b 43 45 32 37 34 34 46 46 2d 35 37 46 45 2d 34 32 41 43 2d 39 46 30 44 2d 37 43 33 38 43 30 30 45 30 30 45 38 7d } //1 {CE2744FF-57FE-42AC-9F0D-7C38C00E00E8}
		$a_01_5 = {7b 41 31 33 45 36 44 30 34 2d 31 37 42 33 2d 34 30 46 43 2d 42 36 39 41 2d 43 34 37 39 31 34 42 41 33 37 37 45 7d } //1 {A13E6D04-17B3-40FC-B69A-C47914BA377E}
		$a_01_6 = {43 61 73 68 6f 6e 20 4e 63 53 65 72 76 69 63 65 } //2 Cashon NcService
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 2f 61 70 70 2f 75 6e 69 6e 73 74 61 6c 6c 2e 70 68 70 3f } //4 http://www.cashon.co.kr/app/uninstall.php?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*4) >=12
 
}
rule BrowserModifier_Win32_CashOn_7{
	meta:
		description = "BrowserModifier:Win32/CashOn,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 61 73 68 6f 6e 2e 63 6f 2e 6b 72 } //1 cashon.co.kr
		$a_01_1 = {61 75 63 74 69 6f 6e 2e 63 6f 2e 6b 72 } //1 auction.co.kr
		$a_01_2 = {64 6e 73 68 6f 70 2e 63 6f 2e 6b 72 } //1 dnshop.co.kr
		$a_01_3 = {63 6a 6d 61 6c 6c 2e 63 6f 2e 6b 72 } //1 cjmall.co.kr
		$a_01_4 = {67 6d 61 72 6b 65 74 2e 63 6f 2e 6b 72 } //1 gmarket.co.kr
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_7 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}