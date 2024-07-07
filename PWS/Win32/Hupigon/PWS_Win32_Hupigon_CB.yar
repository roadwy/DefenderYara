
rule PWS_Win32_Hupigon_CB{
	meta:
		description = "PWS:Win32/Hupigon.CB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
		$a_00_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 \Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {48 41 43 4b 45 52 2e 63 6f 6d 2e 63 6e } //1 HACKER.com.cn
		$a_01_3 = {4e 6f 52 65 61 6c 4d 6f 64 65 } //1 NoRealMode
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}