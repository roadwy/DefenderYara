
rule Worm_Win32_Datheens_D{
	meta:
		description = "Worm:Win32/Datheens.D,SIGNATURE_TYPE_PEHSTR,25 00 25 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //9 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5c 44 65 61 74 68 2e 65 78 65 } //5 \Death.exe
		$a_01_2 = {63 3a 5c 70 61 73 73 2e 64 69 63 } //5 c:\pass.dic
		$a_01_3 = {6e 65 74 20 73 74 6f 70 20 73 65 72 76 65 72 20 2f 79 } //5 net stop server /y
		$a_01_4 = {44 65 64 6c 6c 31 } //5 Dedll1
		$a_01_5 = {64 6c 6c 66 69 6c 65 31 } //5 dllfile1
		$a_01_6 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SoftWare\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {5c 77 75 61 75 63 6c 74 2e 65 78 65 } //1 \wuauclt.exe
		$a_01_8 = {5c 73 70 6f 6f 6c 73 76 2e 65 78 65 } //1 \spoolsv.exe
	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=37
 
}