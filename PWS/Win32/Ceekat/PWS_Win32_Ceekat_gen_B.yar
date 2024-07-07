
rule PWS_Win32_Ceekat_gen_B{
	meta:
		description = "PWS:Win32/Ceekat.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 Content-Type: application/x-www-form-urlencoded
		$a_00_1 = {61 63 74 69 6f 6e 3d 67 65 74 79 78 6c 6f 67 69 6e 26 75 3d } //1 action=getyxlogin&u=
		$a_01_2 = {61 63 74 69 6f 6e 3d 67 65 74 75 70 6f 73 26 6d 61 63 3d } //1 action=getupos&mac=
		$a_01_3 = {61 63 74 69 6f 6e 3d 67 65 74 6d 61 63 } //1 action=getmac
		$a_01_4 = {57 30 57 2e 65 78 65 } //1 W0W.exe
		$a_00_5 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_00_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_00_7 = {45 78 70 6c 6f 72 65 72 2e 45 58 45 } //1 Explorer.EXE
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}