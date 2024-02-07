
rule Backdoor_Win32_PcClient_DG{
	meta:
		description = "Backdoor:Win32/PcClient.DG,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 73 } //01 00  http://%s
		$a_00_1 = {43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 } //01 00  Cache-Control: no-cache
		$a_00_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 } //01 00  Connection: Keep-Alive
		$a_00_3 = {53 4f 46 54 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00  SOFTware\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_4 = {5c 53 56 43 48 4f 53 54 2e 45 58 45 20 2d 6b } //01 00  \SVCHOST.EXE -k
		$a_00_5 = {53 65 72 76 69 63 65 44 6c 6c } //01 00  ServiceDll
		$a_00_6 = {50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00  POST /%s HTTP/1.1
		$a_00_7 = {43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 } //01 00  CurrentControlSet
		$a_00_8 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00  OpenSCManagerA
		$a_00_9 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_00_10 = {4d 61 69 6e 57 6f 72 6b } //01 00  MainWork
		$a_00_11 = {47 55 41 4e 50 41 49 2e 45 58 45 } //01 00  GUANPAI.EXE
		$a_00_12 = {53 55 4f 48 41 2e 45 58 45 } //01 00  SUOHA.EXE
		$a_02_13 = {33 c0 8d 7d 81 f3 ab 66 ab aa c6 45 80 90 01 01 c6 45 81 90 01 01 c6 45 82 90 01 01 c6 45 83 90 01 01 c6 45 84 90 01 01 c6 45 85 90 01 01 c6 45 86 90 01 01 c6 45 87 90 01 01 c6 45 88 90 01 01 c6 45 89 90 01 01 c6 45 8a 90 00 } //01 00 
		$a_02_14 = {b9 ff 00 00 00 33 c0 8d bd 90 01 02 ff ff f3 ab 66 ab aa 68 00 04 00 00 8d 85 90 01 02 ff ff 50 6a 00 8b 8d 90 01 02 ff ff 51 e8 90 01 02 00 00 89 85 90 01 02 ff ff 8b 95 90 01 02 ff ff 52 ff 15 90 01 02 00 10 83 bd 90 01 02 ff ff 00 76 49 8d 85 90 01 02 ff ff 50 ff 15 90 01 02 00 10 83 c4 04 68 90 01 02 00 10 8d 8d 90 01 02 ff ff 51 ff 15 90 01 02 00 10 83 c4 08 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}