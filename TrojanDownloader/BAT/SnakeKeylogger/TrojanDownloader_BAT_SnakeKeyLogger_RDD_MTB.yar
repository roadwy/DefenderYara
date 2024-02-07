
rule TrojanDownloader_BAT_SnakeKeyLogger_RDD_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeyLogger.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 39 62 30 64 65 37 64 2d 31 64 63 65 2d 34 64 61 62 2d 39 33 64 31 2d 62 39 30 61 36 63 34 35 35 30 37 32 } //01 00  39b0de7d-1dce-4dab-93d1-b90a6c455072
		$a_01_1 = {43 00 6e 00 6d 00 70 00 78 00 62 00 64 00 69 00 6e 00 78 00 6e 00 2e 00 50 00 77 00 6f 00 76 00 79 00 79 00 6f 00 6d 00 62 00 67 00 74 00 68 00 64 00 67 00 6c 00 72 00 68 00 71 00 62 00 76 00 66 00 } //01 00  Cnmpxbdinxn.Pwovyyombgthdglrhqbvf
		$a_01_2 = {53 00 74 00 69 00 6d 00 6e 00 74 00 6d 00 77 00 6c 00 6d 00 6f 00 63 00 64 00 69 00 61 00 70 00 74 00 6f 00 68 00 } //01 00  Stimntmwlmocdiaptoh
		$a_01_3 = {2f 00 2f 00 31 00 38 00 35 00 2e 00 32 00 34 00 36 00 2e 00 32 00 32 00 30 00 2e 00 32 00 31 00 30 00 2f 00 49 00 78 00 63 00 68 00 73 00 70 00 2e 00 62 00 6d 00 70 00 } //02 00  //185.246.220.210/Ixchsp.bmp
		$a_01_4 = {07 09 07 8e 69 5d 91 06 09 91 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}