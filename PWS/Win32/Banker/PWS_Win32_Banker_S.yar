
rule PWS_Win32_Banker_S{
	meta:
		description = "PWS:Win32/Banker.S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 65 72 63 6c 65 2e 6e 65 74 2f 2f 73 71 6c 2e 70 68 70 } //1 xercle.net//sql.php
		$a_01_1 = {78 65 72 63 6c 65 73 2e 65 78 65 } //1 xercles.exe
		$a_01_2 = {78 65 72 63 6c 65 2e 64 6c 6c } //1 xercle.dll
		$a_01_3 = {65 76 64 61 74 32 2e 64 6d 63 } //1 evdat2.dmc
		$a_03_4 = {8b 55 cc b8 90 01 03 00 e8 90 01 04 85 c0 0f 85 90 01 02 00 00 8d 45 c8 8b d3 e8 90 01 04 8b 55 c8 b8 90 01 03 00 e8 90 01 04 85 c0 75 3a 8d 45 c4 8b d3 e8 90 01 04 8b 55 c4 b8 c0 42 4d 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}