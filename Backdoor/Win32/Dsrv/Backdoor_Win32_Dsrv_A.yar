
rule Backdoor_Win32_Dsrv_A{
	meta:
		description = "Backdoor:Win32/Dsrv.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 54 68 75 6d 62 62 73 2e 54 4d 50 } //1 ~Thumbbs.TMP
		$a_01_1 = {52 75 6e 44 6c 6c 33 32 78 56 64 2e 65 78 65 } //1 RunDll32xVd.exe
		$a_01_2 = {55 72 6c 44 6f 77 6e 46 69 6c 65 41 6e 64 52 75 6e } //1 UrlDownFileAndRun
		$a_01_3 = {55 70 53 65 72 76 65 46 69 6c 65 } //1 UpServeFile
		$a_01_4 = {63 3a 5c 44 4c 4c 53 65 72 76 69 63 65 2e 54 58 54 } //1 c:\DLLService.TXT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}