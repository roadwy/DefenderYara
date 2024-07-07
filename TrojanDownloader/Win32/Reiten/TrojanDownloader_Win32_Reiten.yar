
rule TrojanDownloader_Win32_Reiten{
	meta:
		description = "TrojanDownloader:Win32/Reiten,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 65 72 31 30 2e 69 6e 66 6f 2f 6e 32 69 76 63 2e 65 78 65 } //2 http://www.tier10.info/n2ivc.exe
		$a_01_1 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c } //1 \ExecPri.dll
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 65 72 31 30 2e 69 6e 66 6f 2f 34 72 74 36 36 69 2e 65 78 65 } //2 http://www.tier10.info/4rt66i.exe
		$a_01_3 = {5c 69 65 78 70 72 65 73 73 61 2e 65 78 65 } //1 \iexpressa.exe
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 65 72 31 30 2e 69 6e 66 6f 2f 34 63 69 61 73 2e 65 78 65 } //2 http://www.tier10.info/4cias.exe
		$a_01_5 = {5c 47 65 74 74 69 6e 67 53 74 61 72 74 65 64 61 2e 65 78 65 } //1 \GettingStarteda.exe
		$a_01_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 65 72 31 30 2e 69 6e 66 6f 2f 65 63 63 2e 65 78 65 } //2 http://www.tier10.info/ecc.exe
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 69 65 72 31 30 2e 69 6e 66 6f 2f 73 32 31 61 63 6c 74 2e 65 78 65 } //2 http://www.tier10.info/s21aclt.exe
		$a_01_8 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //10 Nullsoft Install System
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*10) >=15
 
}