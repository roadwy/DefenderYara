
rule PWS_Win32_QQpass_CJ{
	meta:
		description = "PWS:Win32/QQpass.CJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {51 51 2e 65 78 65 } //1 QQ.exe
		$a_00_1 = {6c 6f 67 69 6e 2e 64 6c 6c } //1 login.dll
		$a_00_2 = {64 65 6c 20 2f 41 3a 48 20 22 25 73 22 } //1 del /A:H "%s"
		$a_00_3 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 if exist "%s" goto Repeat
		$a_01_4 = {8d 51 01 8b 4c 24 04 56 0f b6 31 6b c0 21 03 c6 41 4a 75 f4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}