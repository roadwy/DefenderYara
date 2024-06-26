
rule TrojanDownloader_Win32_Banload_ZJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZJ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0f 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2f 72 65 64 69 72 65 63 74 90 02 02 2e 68 74 6d 6c 90 00 } //01 00 
		$a_01_1 = {31 31 2e 31 31 2e 31 2e 39 38 25 } //01 00  11.11.1.98%
		$a_01_2 = {31 31 30 2e 32 30 30 2e 31 2e 34 25 } //01 00  110.200.1.4%
		$a_01_3 = {31 31 32 2e 31 36 38 2e 32 35 32 2e 31 30 25 } //01 00  112.168.252.10%
		$a_01_4 = {31 32 2e 31 31 2e 31 2e 39 38 25 } //01 00  12.11.1.98%
		$a_01_5 = {31 32 2e 34 34 2e 31 31 2e 31 25 } //01 00  12.44.11.1%
		$a_01_6 = {31 32 30 2e 32 30 30 2e 31 2e 34 25 } //01 00  120.200.1.4%
		$a_01_7 = {31 38 2e 31 32 2e 33 34 2e 34 32 25 } //01 00  18.12.34.42%
		$a_01_8 = {31 39 2e 32 33 2e 31 31 2e 33 30 25 } //01 00  19.23.11.30%
		$a_01_9 = {31 39 31 2e 31 36 38 2e 33 33 2e 31 31 30 25 } //01 00  191.168.33.110%
		$a_01_10 = {31 39 34 2e 31 36 38 2e 33 33 2e 31 31 30 25 } //01 00  194.168.33.110%
		$a_01_11 = {32 32 32 2e 32 34 2e 39 34 2e 31 35 25 } //01 00  222.24.94.15%
		$a_01_12 = {36 31 2e 31 34 32 2e 38 33 2e 32 32 37 25 } //01 00  61.142.83.227%
		$a_01_13 = {39 38 2e 31 32 2e 33 32 2e 33 31 25 } //01 00  98.12.32.31%
		$a_02_14 = {43 3a 5c 54 45 4d 50 5c 90 02 08 5c 65 6e 63 72 79 70 74 90 02 06 2e 62 61 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}