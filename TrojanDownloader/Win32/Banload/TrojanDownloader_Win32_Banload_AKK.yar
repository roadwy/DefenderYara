
rule TrojanDownloader_Win32_Banload_AKK{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKK,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8c 00 78 00 03 00 00 64 00 "
		
	strings :
		$a_01_0 = {50 74 55 38 38 6f 6b 69 49 45 69 6d 48 79 2f 74 6a 68 53 59 45 } //28 00  PtU88okiIEimHy/tjhSYE
		$a_01_1 = {71 45 63 75 77 6b 39 30 2b 71 4c 35 33 74 72 44 2b 41 57 6b 63 } //14 00  qEcuwk90+qL53trD+AWkc
		$a_01_2 = {78 2b 38 53 59 2b 70 72 62 67 62 72 49 6e 50 7a 4e 51 31 50 6b 68 66 42 36 72 35 4e 4d 78 71 6b 33 78 50 46 5a 44 34 50 5a 30 4d 3d } //00 00  x+8SY+prbgbrInPzNQ1PkhfB6r5NMxqk3xPFZD4PZ0M=
	condition:
		any of ($a_*)
 
}