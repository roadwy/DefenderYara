
rule PWS_Win32_Hupigon_CA{
	meta:
		description = "PWS:Win32/Hupigon.CA,SIGNATURE_TYPE_PEHSTR,09 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {51 4f 44 4e 56 44 2e 63 6f 6d 2e 63 6e 5f 4d 55 54 45 58 } //3 QODNVD.com.cn_MUTEX
		$a_01_1 = {75 6e 69 6e 73 74 61 6c 2e 62 61 74 } //1 uninstal.bat
		$a_01_2 = {69 66 20 65 78 69 73 74 20 22 } //1 if exist "
		$a_01_3 = {67 6f 74 6f 20 74 72 79 } //1 goto try
		$a_01_4 = {64 65 6c 20 25 30 } //1 del %0
		$a_01_5 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 software\microsoft\windows\currentversion\run
		$a_01_6 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 77 69 6e 6f 6c 64 61 70 70 } //1 software\microsoft\windows\currentversion\policies\winoldapp
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}