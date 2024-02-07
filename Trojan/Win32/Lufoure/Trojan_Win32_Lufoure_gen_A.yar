
rule Trojan_Win32_Lufoure_gen_A{
	meta:
		description = "Trojan:Win32/Lufoure.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 0f 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 49 6e 69 74 52 65 67 4b 65 79 } //01 00  CurrentControlSet\Control\InitRegKey
		$a_00_1 = {49 6e 69 74 52 65 67 4b 65 79 5c 67 65 6f 69 6e 66 6f } //01 00  InitRegKey\geoinfo
		$a_00_2 = {45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //02 00  Explorer\Browser Helper Objects
		$a_00_3 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2d 73 } //02 00  regsvr32.exe -s
		$a_00_4 = {72 65 67 73 76 72 33 32 2e 65 78 65 20 2d 75 20 2d 73 } //01 00  regsvr32.exe -u -s
		$a_00_5 = {61 6c 77 61 79 73 6f 66 66 } //01 00  alwaysoff
		$a_00_6 = {62 6f 6f 74 2e 69 6e 69 } //01 00  boot.ini
		$a_00_7 = {69 6e 69 74 4e 6f 74 41 6c 69 76 65 } //03 00  initNotAlive
		$a_00_8 = {7b 31 45 36 43 45 34 43 44 2d 31 36 31 42 2d 34 38 34 37 2d 42 38 42 46 2d } //02 00  {1E6CE4CD-161B-4847-B8BF-
		$a_00_9 = {63 6f 75 6e 74 2e 70 68 70 3f 75 73 65 72 3d } //01 00  count.php?user=
		$a_00_10 = {40 65 63 68 6f 20 6f 66 66 } //02 00  @echo off
		$a_00_11 = {3a 64 65 6c 66 69 6c 65 } //01 00  :delfile
		$a_00_12 = {64 65 6c 20 25 31 } //02 00  del %1
		$a_00_13 = {69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 64 65 6c 66 69 6c 65 } //01 00  if exist %1 goto delfile
		$a_00_14 = {69 65 78 70 6c 6f 72 65 5b 31 5d 2e 65 78 65 } //01 00  iexplore[1].exe
		$a_00_15 = {73 6f 78 31 2e 65 78 65 } //01 00  sox1.exe
		$a_01_16 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}