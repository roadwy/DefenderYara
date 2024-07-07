
rule TrojanDropper_Win32_Startpage_E{
	meta:
		description = "TrojanDropper:Win32/Startpage.E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 65 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 69 6e 74 65 22 26 22 72 6e 65 74 65 78 70 6c 6f 72 65 72 2e 61 70 70 22 26 22 6c 69 63 61 74 22 26 22 69 6f 6e 22 29 } //4 ie=createobject("inte"&"rnetexplorer.app"&"licat"&"ion")
		$a_01_1 = {69 65 2e 6e 61 76 69 67 61 74 65 20 22 68 22 26 22 74 74 22 26 22 70 3a 2f 2f 77 77 77 2e 31 22 26 22 31 36 36 66 2e 63 6f 22 26 22 6d 2f 3f 34 32 39 } //4 ie.navigate "h"&"tt"&"p://www.1"&"166f.co"&"m/?429
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 59 7c 20 63 61 63 6c 73 } //1 cmd.exe /c echo Y| cacls
		$a_01_3 = {6c 61 74 6f 72 5c 49 6e 74 65 72 6e 61 74 20 20 45 78 70 6c 6f 72 65 72 } //1 lator\Internat  Explorer
		$a_01_4 = {77 77 77 2e 31 31 36 36 66 2e 63 6f 6d 2f 3f 70 6f 70 } //1 www.1166f.com/?pop
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}