
rule PWS_Win32_Legmir_B{
	meta:
		description = "PWS:Win32/Legmir.B,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 08 00 00 "
		
	strings :
		$a_01_0 = {6c 65 67 65 6e 64 20 6f 66 20 6d 69 72 32 } //10 legend of mir2
		$a_01_1 = {2f 69 6d 61 69 6c 2f 73 65 6e 64 6d 61 69 6c 2e 61 73 70 3f 74 6f 6d 61 69 6c 3d } //10 /imail/sendmail.asp?tomail=
		$a_01_2 = {50 4f 53 54 00 00 00 00 48 54 54 50 2f 31 2e 30 } //10
		$a_01_3 = {4c 69 6e 65 61 67 65 20 57 69 6e 64 6f 77 73 20 43 6c 69 65 6e 74 } //10 Lineage Windows Client
		$a_01_4 = {45 47 68 6f 73 74 2e 65 78 65 } //1 EGhost.exe
		$a_01_5 = {50 61 73 73 77 6f 72 64 47 75 61 72 64 2e 65 78 65 } //1 PasswordGuard.exe
		$a_01_6 = {6b 76 61 70 66 77 2e 65 78 65 } //1 kvapfw.exe
		$a_01_7 = {49 70 61 72 6d 6f 72 2e 65 78 65 } //1 Iparmor.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=42
 
}