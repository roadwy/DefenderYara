
rule TrojanDownloader_Win32_Obvod_A{
	meta:
		description = "TrojanDownloader:Win32/Obvod.A,SIGNATURE_TYPE_PEHSTR,33 00 33 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //0a 00  InternetReadFile
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  WriteProcessMemory
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //0a 00  CreateRemoteThread
		$a_01_3 = {3c 49 46 52 41 4d 45 20 46 52 41 4d 45 42 4f 52 44 45 52 3d 30 } //0a 00  <IFRAME FRAMEBORDER=0
		$a_01_4 = {3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 6a 61 76 61 73 63 72 69 70 74 22 20 73 72 63 3d 22 25 73 22 3e 3c 2f 73 63 72 69 70 74 3e } //01 00  <script language="javascript" src="%s"></script>
		$a_01_5 = {39 31 2e 31 34 32 2e 36 37 2e 35 31 } //01 00  91.142.67.51
		$a_01_6 = {31 39 34 2e 31 32 36 2e 31 39 33 2e 31 36 31 } //01 00  194.126.193.161
		$a_01_7 = {32 30 39 2e 31 36 37 2e 31 31 31 2e 31 31 30 } //01 00  209.167.111.110
		$a_01_8 = {68 74 74 70 3a 2f 2f 25 73 2f 72 6a 73 61 2f 73 65 6c 65 63 74 2e 70 68 70 3f 61 3d 25 73 26 62 3d 25 64 26 63 3d 25 64 } //00 00  http://%s/rjsa/select.php?a=%s&b=%d&c=%d
	condition:
		any of ($a_*)
 
}