
rule BrowserModifier_Win32_YokSearch{
	meta:
		description = "BrowserModifier:Win32/YokSearch,SIGNATURE_TYPE_PEHSTR,08 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {79 6f 6b 2e 64 6c 6c } //1 yok.dll
		$a_01_1 = {79 6f 6b 2e 65 78 65 } //1 yok.exe
		$a_01_2 = {59 4f 4b 2e 69 63 6f } //1 YOK.ico
		$a_01_3 = {59 4f 4b 55 50 44 57 43 6c 61 73 73 } //1 YOKUPDWClass
		$a_01_4 = {77 77 77 2e 79 6f 6b 2e 63 6f 6d 2f 67 6f } //1 www.yok.com/go
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 59 4f 4b 5c 43 6f 6f 70 } //1 Software\YOK\Coop
		$a_01_6 = {53 6f 66 74 57 61 72 65 5c 59 6f 6b 5c 54 6f 6f 6c 62 61 72 } //1 SoftWare\Yok\Toolbar
		$a_01_7 = {5c 79 6f 6b 73 63 68 2e 68 74 6d } //1 \yoksch.htm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}
rule BrowserModifier_Win32_YokSearch_2{
	meta:
		description = "BrowserModifier:Win32/YokSearch,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 00 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 59 4b 45 45 50 45 52 00 00 44 65 76 69 63 65 4e 61 6d 65 00 } //4
		$a_01_1 = {54 59 4b 65 65 70 65 72 2e 76 78 64 } //4 TYKeeper.vxd
		$a_01_2 = {61 75 74 6f 6c 69 76 65 2e 64 6c 6c } //3 autolive.dll
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_01_4 = {52 65 67 43 72 65 61 74 65 4b 65 79 45 78 41 } //1 RegCreateKeyExA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}
rule BrowserModifier_Win32_YokSearch_3{
	meta:
		description = "BrowserModifier:Win32/YokSearch,SIGNATURE_TYPE_PEHSTR,0e 00 0c 00 10 00 00 "
		
	strings :
		$a_01_0 = {62 6c 6f 63 6b 2e 79 6f 6b 2e 63 6f 6d } //1 block.yok.com
		$a_01_1 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 59 6f 6b 62 61 72 } //1 SoftWare\Microsoft\Internet Explorer\Yokbar
		$a_01_2 = {77 77 77 2e 79 6f 6b 2e 63 6f 6d 2f 67 6f } //1 www.yok.com/go
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 65 6e 75 45 78 74 5c 59 4f 4b } //1 Software\Microsoft\Internet Explorer\MenuExt\YOK
		$a_01_4 = {79 6f 6b 79 6d 74 2e 65 78 65 } //1 yokymt.exe
		$a_01_5 = {79 6f 6b 79 6d 74 64 61 74 61 2e 79 6d 74 } //1 yokymtdata.ymt
		$a_01_6 = {79 6f 6b 75 70 64 61 74 65 2e 64 61 74 } //1 yokupdate.dat
		$a_01_7 = {79 6f 6b 6c 6f 67 2e 74 78 74 } //1 yoklog.txt
		$a_01_8 = {79 6f 6b 64 6f 77 2e 65 78 65 } //1 yokdow.exe
		$a_01_9 = {79 6f 6b 73 63 68 2e 68 74 6d } //1 yoksch.htm
		$a_01_10 = {79 6f 6b 64 61 74 2e 65 78 65 } //1 yokdat.exe
		$a_01_11 = {79 6f 6b 70 72 6f 2e 65 78 65 } //1 yokpro.exe
		$a_01_12 = {79 6f 6b 75 70 64 2e 65 78 65 } //1 yokupd.exe
		$a_01_13 = {79 6f 6b 62 61 72 2e 69 6e 66 } //1 yokbar.inf
		$a_01_14 = {79 6f 6b 63 6f 6c 2e 64 6c 6c } //1 yokcol.dll
		$a_01_15 = {79 6f 6b 62 61 72 2e 64 6c 6c } //1 yokbar.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=12
 
}