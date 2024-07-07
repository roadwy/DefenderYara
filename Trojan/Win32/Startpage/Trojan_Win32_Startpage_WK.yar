
rule Trojan_Win32_Startpage_WK{
	meta:
		description = "Trojan:Win32/Startpage.WK,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {51 2d 24 2d 45 58 45 } //1 Q-$-EXE
		$a_01_1 = {64 65 6c 20 25 30 } //1 del %0
		$a_01_2 = {51 38 38 38 2e 64 6c 6c } //1 Q888.dll
		$a_01_3 = {51 39 39 39 2e 64 6c 6c } //1 Q999.dll
		$a_01_4 = {78 6c 6f 6f 6f 2e 64 6c 6c } //1 xlooo.dll
		$a_01_5 = {78 6c 6e 6e 6e 2e 64 6c 6c } //1 xlnnn.dll
		$a_01_6 = {31 37 34 2e 31 33 39 2e 32 2e 32 33 36 2f 47 6f 2e 61 73 68 78 3f 4d 61 63 3d } //1 174.139.2.236/Go.ashx?Mac=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}