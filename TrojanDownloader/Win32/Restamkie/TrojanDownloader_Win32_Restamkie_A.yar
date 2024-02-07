
rule TrojanDownloader_Win32_Restamkie_A{
	meta:
		description = "TrojanDownloader:Win32/Restamkie.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 74 74 70 73 3a 2f 2f 73 74 6f 72 61 67 65 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d 2f 63 6f 6e 76 69 74 65 2d 32 30 31 35 2f 90 02 10 2e 7a 69 70 90 00 } //01 00 
		$a_01_1 = {52 75 6e 6e 69 6e 67 61 6d 65 73 2e 65 78 65 } //01 00  Runningames.exe
		$a_01_2 = {5c 61 4b 33 31 4d 41 53 54 45 52 30 32 2e 65 78 65 } //01 00  \aK31MASTER02.exe
		$a_01_3 = {5c 74 6f 79 73 2e 64 61 74 } //01 00  \toys.dat
		$a_03_4 = {3b 04 24 5a 58 74 90 01 01 33 c0 55 68 90 01 04 64 ff 30 64 89 20 68 90 01 04 8b 45 f8 50 e8 90 01 04 8b f0 89 f3 85 f6 74 90 01 01 6a 00 6a 00 8b 45 f4 e8 90 01 04 50 8b 45 fc e8 90 01 04 50 6a 00 ff d3 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 43 
	condition:
		any of ($a_*)
 
}