
rule TrojanProxy_Win32_Wopla_gen_C{
	meta:
		description = "TrojanProxy:Win32/Wopla.gen!C,SIGNATURE_TYPE_PEHSTR,47 00 47 00 0a 00 00 "
		
	strings :
		$a_01_0 = {25 73 78 74 65 6d 70 78 2e } //10 %sxtempx.
		$a_01_1 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e } //10 MAIL FROM:<%s>
		$a_01_2 = {5c 77 6f 72 6b 5f 73 76 6e 5c 6d 61 64 6f 6e 6e 61 } //10 \work_svn\madonna
		$a_01_3 = {5c 70 61 63 6b 65 64 5f 49 6e 73 74 61 6c 6c 65 72 } //10 \packed_Installer
		$a_01_4 = {67 6c 2e 6e 75 6c 6c 61 64 64 72 65 73 73 2e 63 6f 6d } //10 gl.nulladdress.com
		$a_01_5 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 6d 61 6b 65 5f 64 6c 6c 2e 62 61 74 } //10 cmd.exe /c "make_dll.bat
		$a_01_6 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 } //10 %s:*:Enabled:Windows Update
		$a_01_7 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 72 73 76 70 73 70 2e 64 6c 6c } //10 %systemroot%\system32\rsvpsp.dll
		$a_01_8 = {41 46 31 33 33 44 34 45 2d 34 42 33 35 2d 34 62 64 38 2d 39 41 33 30 2d 43 45 36 41 34 38 30 45 35 33 44 35 } //1 AF133D4E-4B35-4bd8-9A30-CE6A480E53D5
		$a_01_9 = {37 44 41 35 31 41 41 38 2d 41 35 46 32 2d 34 36 63 63 2d 42 38 39 32 2d 41 33 44 46 31 45 41 34 37 36 32 46 } //1 7DA51AA8-A5F2-46cc-B892-A3DF1EA4762F
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=71
 
}