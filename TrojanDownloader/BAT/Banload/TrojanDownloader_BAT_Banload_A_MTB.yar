
rule TrojanDownloader_BAT_Banload_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Banload.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 72 00 6f 00 6f 00 6d 00 6d 00 61 00 73 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  /roommaster.exe
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6f 00 66 00 69 00 63 00 69 00 6e 00 61 00 66 00 69 00 6e 00 61 00 6e 00 63 00 69 00 65 00 69 00 72 00 6f 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 } //01 00  http://oficinafinancieiro.website
		$a_01_2 = {24 34 34 33 62 34 31 34 36 2d 64 32 36 63 2d 34 65 33 64 2d 38 32 32 39 2d 33 66 30 39 61 33 62 30 30 34 65 64 } //01 00  $443b4146-d26c-4e3d-8229-3f09a3b004ed
		$a_00_3 = {72 2d 00 00 70 28 48 00 00 0a 26 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}