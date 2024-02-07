
rule TrojanDownloader_Win32_Dryanonis_A{
	meta:
		description = "TrojanDownloader:Win32/Dryanonis.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 6c 6f 67 73 2f 69 6e 73 74 2e 70 68 70 } //02 00  /logs/inst.php
		$a_01_1 = {65 75 67 65 6e 65 5f 64 61 6e 69 6c 6f 76 40 79 61 68 6f 6f 2e 63 6f 6d 7c 7c 7c } //01 00  eugene_danilov@yahoo.com|||
		$a_01_2 = {6b 61 72 6c 68 75 67 68 61 6e 2e 63 6f 6d } //01 00  karlhughan.com
		$a_01_3 = {67 72 65 65 6e 67 72 61 73 73 6f 75 74 64 6f 6f 72 73 65 72 76 69 63 65 73 2e 63 6f 6d } //01 00  greengrassoutdoorservices.com
		$a_01_4 = {74 72 61 64 65 6d 61 72 6b 2d 73 61 66 65 74 79 2e 63 6f 6d } //01 00  trademark-safety.com
		$a_01_5 = {7c 7c 7c 32 32 32 32 32 32 32 32 32 32 32 } //01 00  |||22222222222
		$a_01_6 = {32 37 37 38 32 34 38 37 33 35 32 30 32 39 33 39 33 32 30 33 39 34 30 36 31 36 34 33 39 38 30 31 32 39 30 33 39 34 39 30 35 37 32 36 37 32 38 38 39 34 37 38 30 35 38 35 35 31 30 31 35 33 39 33 37 } //00 00  27782487352029393203940616439801290394905726728894780585510153937
		$a_00_7 = {80 10 00 00 } //57 48 
	condition:
		any of ($a_*)
 
}