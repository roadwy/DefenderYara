
rule TrojanDownloader_Win32_Delf_VC{
	meta:
		description = "TrojanDownloader:Win32/Delf.VC,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 49 4e 44 4f 57 53 5c 48 65 6c 70 5c 73 76 63 68 6f 73 74 2e 65 } //01 00  WINDOWS\Help\svchost.e
		$a_01_1 = {6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d } //02 00  kkill /f /t /im
		$a_01_2 = {77 69 6e 64 6f 77 73 5c 68 65 6c 70 5c 63 73 72 73 2e 65 } //01 00  windows\help\csrs.e
		$a_01_3 = {2f 63 20 73 63 20 63 6f 6e 66 69 67 20 72 64 73 65 73 73 6d 67 72 } //02 00  /c sc config rdsessmgr
		$a_01_4 = {79 73 2d 66 2e 79 73 31 36 38 2e 63 6f 6d 2f } //00 00  ys-f.ys168.com/
	condition:
		any of ($a_*)
 
}