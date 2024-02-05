
rule TrojanDownloader_BAT_Shmandaler_A{
	meta:
		description = "TrojanDownloader:BAT/Shmandaler.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 4d 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 } //01 00 
		$a_01_1 = {4d 41 67 65 6e 74 00 41 73 73 65 6d 62 6c 79 54 } //01 00 
		$a_01_2 = {21 4d 00 41 00 67 00 65 00 6e 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //00 00 
	condition:
		any of ($a_*)
 
}