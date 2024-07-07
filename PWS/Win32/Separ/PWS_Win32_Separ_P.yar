
rule PWS_Win32_Separ_P{
	meta:
		description = "PWS:Win32/Separ.P,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 41 00 64 00 6f 00 62 00 65 00 5c 00 50 00 64 00 66 00 5c 00 6c 00 6f 00 77 00 5c 00 } //1 %APPDATA%\Local\Adobe\Pdf\low\
		$a_01_1 = {61 64 6f 62 65 30 32 2e 62 61 74 } //1 adobe02.bat
		$a_01_2 = {61 64 6f 62 65 6c 2e 76 62 73 } //1 adobel.vbs
		$a_01_3 = {61 64 6f 62 65 70 64 66 2e 65 78 65 } //1 adobepdf.exe
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}