
rule PWS_Win32_Fakemsn_L{
	meta:
		description = "PWS:Win32/Fakemsn.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 6d 73 6e 6d 73 67 72 2e 65 78 65 20 2f 66 } //1 taskkill /im msnmsgr.exe /f
		$a_01_1 = {2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 } //1 /upload.php
		$a_03_2 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 90 04 01 02 66 67 00 5c 00 90 00 } //1
		$a_01_3 = {53 00 69 00 67 00 6e 00 20 00 49 00 6e 00 } //1 Sign In
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}