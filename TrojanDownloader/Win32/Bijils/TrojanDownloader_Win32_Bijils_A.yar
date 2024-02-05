
rule TrojanDownloader_Win32_Bijils_A{
	meta:
		description = "TrojanDownloader:Win32/Bijils.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 5c 70 69 6f 31 32 2e 64 6c 6c 20 44 6c 6c 44 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_01_1 = {65 71 71 6d 37 2c 2c } //01 00 
		$a_01_2 = {2d 20 4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}