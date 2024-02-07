
rule TrojanDownloader_Win32_Agent_XC{
	meta:
		description = "TrojanDownloader:Win32/Agent.XC,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 10 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_00_1 = {20 2f 71 6e 20 2f 78 } //01 00   /qn /x
		$a_00_2 = {55 52 4c 55 70 64 61 74 65 49 6e 66 6f } //01 00  URLUpdateInfo
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 45 73 65 74 5c 4e 6f 64 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 4d 6f 64 75 6c 65 73 5c 41 4d 4f 4e 5c 53 65 74 74 69 6e 67 73 5c 43 6f 6e 66 69 67 30 30 30 5c 53 65 74 74 69 6e 67 73 } //01 00  SOFTWARE\Eset\Nod\CurrentVersion\Modules\AMON\Settings\Config000\Settings
		$a_01_4 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_00_5 = {65 78 63 5f 6e 75 6d } //01 00  exc_num
		$a_00_6 = {3a 5f 6d 73 69 65 78 65 63 2e 65 78 65 } //01 00  :_msiexec.exe
		$a_00_7 = {73 70 65 72 73 6b } //01 00  spersk
		$a_00_8 = {4d 63 53 68 69 65 6c 64 } //01 00  McShield
		$a_00_9 = {55 6e 69 6e 73 74 61 6c 6c 53 74 72 69 6e 67 } //01 00  UninstallString
		$a_00_10 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 31 00 5c 00 } //02 00  \Device\HarddiskVolume1\
		$a_00_11 = {c9 8b 55 08 33 c0 eb 06 8b ff d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00 } //02 00 
		$a_00_12 = {c9 8b 55 08 33 c0 eb 06 8d 3f d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00 } //02 00 
		$a_00_13 = {c9 ff 75 08 5a 33 c0 eb 06 8d 3f d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00 } //01 00 
		$a_00_14 = {68 74 74 70 3a 2f 2f 61 6c 65 72 74 2d 63 61 2e 63 6f 6d 2f 63 6f 75 6e 74 65 72 31 2f 66 6f 75 74 2e 70 68 70 } //01 00  http://alert-ca.com/counter1/fout.php
		$a_00_15 = {63 6d 64 20 2f 63 20 74 2e 62 61 74 } //00 00  cmd /c t.bat
	condition:
		any of ($a_*)
 
}