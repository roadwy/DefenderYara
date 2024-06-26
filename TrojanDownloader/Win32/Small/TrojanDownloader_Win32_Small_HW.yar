
rule TrojanDownloader_Win32_Small_HW{
	meta:
		description = "TrojanDownloader:Win32/Small.HW,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0e 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 25 25 30 } //02 00  del %%0
		$a_01_1 = {5c 64 65 6b 2e 62 61 74 } //02 00  \dek.bat
		$a_01_2 = {64 65 6c 20 22 25 73 22 } //01 00  del "%s"
		$a_01_3 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //02 00  \drivers\etc\hosts
		$a_01_4 = {25 77 69 6e 64 69 72 25 5c 54 61 73 6b 73 5c 70 69 67 2e 76 62 73 } //02 00  %windir%\Tasks\pig.vbs
		$a_01_5 = {72 73 2e 72 75 6e 20 5c 78 32 32 25 25 77 69 6e 64 69 72 25 25 5c 54 61 73 6b 73 5c 6b 61 76 33 32 2e 65 78 65 22 2c 30 } //01 00  rs.run \x22%%windir%%\Tasks\kav32.exe",0
		$a_01_6 = {7b 36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 7d 5c 6b 61 76 33 32 2e 65 78 65 } //02 00  {645FF040-5081-101B-9F08-00AA002F954E}\kav32.exe
		$a_01_7 = {56 69 72 75 73 } //02 00  Virus
		$a_01_8 = {41 55 54 4f 52 55 4e 2e 49 4e 46 } //01 00  AUTORUN.INF
		$a_01_9 = {54 72 6f 6a 61 6e 48 75 6e 74 65 72 2e 65 78 65 } //01 00  TrojanHunter.exe
		$a_01_10 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 } //01 00  shell\open\Command
		$a_01_11 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //01 00  InternetOpenA
		$a_01_12 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  ZwQuerySystemInformation
		$a_01_13 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}