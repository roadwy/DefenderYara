
rule Trojan_Win32_Startpage_DB{
	meta:
		description = "Trojan:Win32/Startpage.DB,SIGNATURE_TYPE_PEHSTR,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 48 69 64 65 44 65 73 6b 74 6f 70 49 63 6f 6e 73 5c 4e 65 77 53 74 61 72 74 50 61 6e 65 6c 5c 7b 38 37 31 43 35 33 38 30 2d 34 32 41 30 2d 31 30 36 39 2d 41 32 45 41 2d 30 38 30 30 32 42 33 30 33 30 39 44 7d } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{871C5380-42A0-1069-A2EA-08002B30309D}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 49 45 58 50 4f 4c 52 45 } //1 Software\Microsoft\Windows\CurrentVersion\Run\IEXPOLRE
		$a_01_2 = {68 74 74 70 3a 2f 2f 64 2e 62 61 69 64 75 2e 63 6f 6d 2f 69 6e 64 65 78 2e 70 68 70 3f 74 6e 3d 6f 6f 6f 6f 6f 73 5f 70 67 } //1 http://d.baidu.com/index.php?tn=ooooos_pg
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 69 61 33 2e 63 6f 6d } //1 http://www.xia3.com
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 71 71 79 65 2e 63 6f 6d } //1 http://www.qqye.com
		$a_01_5 = {5b 63 63 74 76 30 36 2e 63 6f 6d 5d 2e 6c 6e 6b } //1 [cctv06.com].lnk
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 63 74 76 30 36 2e 63 6f 6d } //1 http://www.cctv06.com
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 6f 75 78 69 77 2e 63 6f 6d } //1 http://www.youxiw.com
		$a_01_8 = {5c 6b 73 74 6f 6f 6c 2e 65 78 65 } //1 \kstool.exe
		$a_01_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 61 68 75 6f 6f 6f 2e 63 6f 6d } //1 http://www.yahuooo.com
		$a_01_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 } //1 Software\Microsoft\Internet Explorer\Main\Start Page
		$a_01_11 = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 6b 65 72 6e 65 6c 20 6c 69 62 72 61 72 79 21 } //1 Failed to load kernel library!
		$a_01_12 = {4e 6f 74 20 66 6f 75 6e 64 20 74 68 65 20 6b 65 72 6e 65 6c 20 6c 69 62 72 61 72 79 21 } //1 Not found the kernel library!
		$a_01_13 = {6b 72 6e 6c 6e 2e 66 6e 65 } //1 krnln.fne
		$a_01_14 = {6b 72 6e 6c 6e 2e 66 6e 72 } //1 krnln.fnr
		$a_01_15 = {57 54 4e 45 20 2f 20 4d 41 44 45 20 42 59 20 45 20 43 4f 4d 50 49 4c 45 52 20 2d 20 57 55 54 41 4f } //1 WTNE / MADE BY E COMPILER - WUTAO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}