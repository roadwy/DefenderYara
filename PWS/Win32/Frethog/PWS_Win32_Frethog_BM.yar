
rule PWS_Win32_Frethog_BM{
	meta:
		description = "PWS:Win32/Frethog.BM,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 31 3d 25 73 26 70 61 73 73 77 6f 72 64 32 3d 25 73 26 73 70 65 63 69 61 6c 53 69 67 6e 3d 25 73 26 63 61 73 68 3d 25 64 26 63 6c 69 65 6e 74 3d } //1 account=%s&password1=%s&password2=%s&specialSign=%s&cash=%d&client=
		$a_01_1 = {26 73 65 72 76 65 72 3d 25 73 26 69 6e 70 75 74 73 6f 75 72 63 65 3d 25 73 26 6c 65 76 65 6c 73 3d 25 64 26 6e 61 6d 65 3d 25 73 26 6f 74 68 65 72 3d 25 73 26 76 65 72 69 66 79 3d 25 73 } //1 &server=%s&inputsource=%s&levels=%d&name=%s&other=%s&verify=%s
		$a_01_2 = {6d 69 62 61 6f 2e 61 73 70 } //1 mibao.asp
		$a_01_3 = {61 63 74 3d 67 65 74 70 6f 73 26 61 63 63 6f 75 6e 74 3d 25 73 } //1 act=getpos&account=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}