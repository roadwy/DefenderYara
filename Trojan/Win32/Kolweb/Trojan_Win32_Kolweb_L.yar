
rule Trojan_Win32_Kolweb_L{
	meta:
		description = "Trojan:Win32/Kolweb.L,SIGNATURE_TYPE_PEHSTR,57 00 57 00 0e 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //20 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects\
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 56 49 44 49 41 20 43 6f 72 70 6f 72 61 74 69 6f 6e 5c 43 70 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 73 } //20 Software\NVIDIA Corporation\Cpanel\Desktops
		$a_01_2 = {54 49 45 42 72 6f 77 73 65 72 48 65 6c 70 65 72 46 61 63 74 6f 72 79 } //20 TIEBrowserHelperFactory
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 72 67 6f 74 61 62 6f 75 74 74 72 6f 75 62 6c 65 73 2e 63 6f 6d 2f 79 65 70 2f } //20 http://www.forgotabouttroubles.com/yep/
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 6c 6c 6f 77 77 68 69 74 65 72 61 62 62 69 74 2e 63 6f 6d 2f 79 65 70 2f } //20 http://www.followwhiterabbit.com/yep/
		$a_01_5 = {6c 61 73 74 64 65 73 6b 74 6f 70 } //1 lastdesktop
		$a_01_6 = {64 65 73 6b 74 6f 70 6c 69 73 74 } //1 desktoplist
		$a_01_7 = {75 73 65 64 64 65 73 6b 74 6f 70 } //1 useddesktop
		$a_01_8 = {4c 61 73 74 20 55 73 65 72 20 49 44 } //1 Last User ID
		$a_01_9 = {44 65 66 61 75 6c 74 20 55 73 65 72 20 49 44 } //1 Default User ID
		$a_01_10 = {4c 61 73 74 43 6f 6e 6e 65 63 74 65 64 } //1 LastConnected
		$a_01_11 = {46 69 72 73 74 43 6f 6e 6e 65 63 74 65 64 } //1 FirstConnected
		$a_01_12 = {64 65 73 63 74 6f 70 5f } //1 desctop_
		$a_01_13 = {73 65 74 74 69 6e 67 73 2e 70 68 70 } //1 settings.php
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=87
 
}