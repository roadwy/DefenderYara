
rule Worm_Win32_Nedky_A{
	meta:
		description = "Worm:Win32/Nedky.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 65 76 69 6c 6d 61 6e 2e 63 6e 2f 6d 32 2e 74 78 74 } //1 http://evilman.cn/m2.txt
		$a_01_1 = {6b 65 6e 64 79 2e 74 78 74 } //1 kendy.txt
		$a_01_2 = {63 6d 64 20 2f 63 20 64 65 6c 20 2f 66 20 2f 61 20 } //1 cmd /c del /f /a 
		$a_01_3 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_4 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 53 65 74 75 70 2e 70 69 66 } //1 shellexecute=Setup.pif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}