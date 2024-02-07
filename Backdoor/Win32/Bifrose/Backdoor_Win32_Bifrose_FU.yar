
rule Backdoor_Win32_Bifrose_FU{
	meta:
		description = "Backdoor:Win32/Bifrose.FU,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {42 69 66 72 6f 73 74 } //0a 00  Bifrost
		$a_00_1 = {73 74 75 62 70 61 74 68 00 } //0a 00 
		$a_01_2 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //0a 00  NtWriteVirtualMemory
		$a_01_3 = {7b 39 42 37 31 44 38 38 43 2d 43 35 39 38 2d 34 39 33 35 2d 43 35 44 31 2d 34 33 41 41 34 44 42 39 30 38 33 36 7d } //0a 00  {9B71D88C-C598-4935-C5D1-43AA4DB90836}
		$a_01_4 = {25 63 25 64 2e 25 64 2e 25 64 2e 25 64 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 75 7c 25 69 7c 25 69 7c 25 75 7c } //01 00  %c%d.%d.%d.%d|%s|%s|%s|%s|%s|%u|%i|%i|%u|
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 65 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 25 73 } //01 00  SOFTWARE\Microsoet\Active Setup\Installed Components\%s
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 65 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //00 00  SOFTWARE\Microsoet\Windows\CurrentVersion\App Paths\iexplore.exe
	condition:
		any of ($a_*)
 
}