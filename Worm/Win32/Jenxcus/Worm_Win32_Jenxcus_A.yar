
rule Worm_Win32_Jenxcus_A{
	meta:
		description = "Worm:Win32/Jenxcus.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6a 77 30 72 6d 2e 70 77 64 2e 72 65 73 6f 75 72 63 65 73 } //3 njw0rm.pwd.resources
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 41 00 6e 00 64 00 20 00 52 00 75 00 6e 00 } //1 Download And Run
		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 Execute cmd.exe
		$a_01_3 = {6f 00 72 00 2c 00 2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 5c 00 2a 00 2e 00 76 00 62 00 73 00 } //1 or,/c del %temp%\*.vbs
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}