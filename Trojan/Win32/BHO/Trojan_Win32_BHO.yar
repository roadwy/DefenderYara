
rule Trojan_Win32_BHO{
	meta:
		description = "Trojan:Win32/BHO,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 38 36 41 34 34 45 46 37 2d 37 38 46 43 2d 34 65 31 38 2d 41 35 36 34 2d 42 31 38 46 38 30 36 46 37 46 35 36 7d } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{86A44EF7-78FC-4e18-A564-B18F806F7F56}
		$a_01_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 2e 44 4c 4c } //1 ConnectionServices.DLL
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_3 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_BHO_2{
	meta:
		description = "Trojan:Win32/BHO,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //1 Microsoft Visual C++ Runtime Library
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 31 38 43 42 31 41 37 42 2d 39 34 43 44 2d 34 35 38 32 2d 38 30 32 32 2d 41 44 41 31 36 38 35 31 45 34 34 42 7d } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{18CB1A7B-94CD-4582-8022-ADA16851E44B}
		$a_01_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 65 72 76 69 63 65 73 2e 44 4c 4c } //1 ConnectionServices.DLL
		$a_01_3 = {67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 2e 63 6f 6d } //1 gofuckyourself.com
		$a_01_4 = {62 62 73 2e 61 64 75 6c 74 77 65 62 6d 61 73 74 65 72 69 6e 66 6f 2e 63 6f 6d } //1 bbs.adultwebmasterinfo.com
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_6 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //1 HttpOpenRequestA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}