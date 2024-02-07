
rule TrojanDownloader_BAT_Bigik_A{
	meta:
		description = "TrojanDownloader:BAT/Bigik.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 55 73 65 72 00 } //01 00 
		$a_03_1 = {64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 2f 00 90 02 32 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_2 = {5b 00 61 00 75 00 74 00 6f 00 6e 00 72 00 75 00 6e 00 5d 00 } //01 00  [autonrun]
		$a_01_3 = {5c 00 50 00 69 00 63 00 74 00 75 00 72 00 65 00 73 00 2e 00 73 00 63 00 72 00 } //01 00  \Pictures.scr
		$a_01_4 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  \autorun.inf
	condition:
		any of ($a_*)
 
}