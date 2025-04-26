
rule TrojanDownloader_Win32_Baser_A{
	meta:
		description = "TrojanDownloader:Win32/Baser.A,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 29 00 0c 00 00 "
		
	strings :
		$a_02_0 = {78 78 2e 35 32 32 6c 6f 76 65 2e 63 6e 2f [0-10] 2e 65 78 65 } //1
		$a_02_1 = {76 76 76 2e 33 78 37 78 2e 63 6e 2f [0-10] 2e 65 78 65 } //1
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 65 6c 65 64 6f 6d 6e 2e 62 61 74 } //1 C:\WINDOWS\SYSTEM32\Deledomn.bat
		$a_00_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 41 6c 6c 65 74 64 65 6c 2e 62 61 74 } //1 C:\WINDOWS\SYSTEM32\Alletdel.bat
		$a_00_4 = {73 65 72 76 65 72 69 65 } //5 serverie
		$a_00_5 = {44 72 69 76 65 72 73 2f 6b 6c 69 66 2e 73 79 73 } //5 Drivers/klif.sys
		$a_00_6 = {3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //5 :\AutoRun.inf
		$a_00_7 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //5 shellexecute=
		$a_00_8 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //5 NoDriveTypeAutoRun
		$a_00_9 = {41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d } //5 Auto\command=
		$a_00_10 = {73 76 63 68 6f 73 74 2e 65 78 65 } //5 svchost.exe
		$a_00_11 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5+(#a_00_6  & 1)*5+(#a_00_7  & 1)*5+(#a_00_8  & 1)*5+(#a_00_9  & 1)*5+(#a_00_10  & 1)*5+(#a_00_11  & 1)*5) >=41
 
}