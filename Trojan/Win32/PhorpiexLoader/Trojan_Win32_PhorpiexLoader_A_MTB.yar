
rule Trojan_Win32_PhorpiexLoader_A_MTB{
	meta:
		description = "Trojan:Win32/PhorpiexLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0e 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 00 62 00 69 00 65 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //02 00  sbiedll.dll
		$a_01_1 = {64 00 62 00 67 00 68 00 65 00 6c 00 70 00 2e 00 64 00 6c 00 6c 00 } //02 00  dbghelp.dll
		$a_01_2 = {61 00 70 00 69 00 5f 00 6c 00 6f 00 67 00 2e 00 64 00 6c 00 6c 00 } //02 00  api_log.dll
		$a_01_3 = {64 00 69 00 72 00 5f 00 77 00 61 00 74 00 63 00 68 00 2e 00 64 00 6c 00 6c 00 } //02 00  dir_watch.dll
		$a_01_4 = {70 00 73 00 74 00 6f 00 72 00 65 00 63 00 2e 00 64 00 6c 00 6c 00 } //02 00  pstorec.dll
		$a_01_5 = {76 00 6d 00 63 00 68 00 65 00 63 00 6b 00 2e 00 64 00 6c 00 6c 00 } //02 00  vmcheck.dll
		$a_01_6 = {77 00 70 00 65 00 73 00 70 00 79 00 2e 00 64 00 6c 00 6c 00 } //02 00  wpespy.dll
		$a_01_7 = {63 6f 6e 6e 65 63 74 20 66 61 69 6c 65 64 20 25 64 } //02 00  connect failed %d
		$a_01_8 = {63 6f 6e 6e 65 63 74 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //02 00  connect successfully
		$a_01_9 = {73 65 6e 64 20 66 61 69 6c 65 64 20 25 64 } //02 00  send failed %d
		$a_01_10 = {72 65 63 76 20 66 61 69 6c 65 64 20 25 64 } //02 00  recv failed %d
		$a_01_11 = {44 6f 77 6e 6c 6f 61 64 20 73 61 6d 70 6c 65 20 73 75 63 63 65 65 64 } //01 00  Download sample succeed
		$a_01_12 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //01 00  GetProcAddress
		$a_01_13 = {4c 6f 61 64 4c 69 62 72 61 72 79 57 } //00 00  LoadLibraryW
	condition:
		any of ($a_*)
 
}