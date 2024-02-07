
rule TrojanDownloader_BAT_Vhoster_A{
	meta:
		description = "TrojanDownloader:BAT/Vhoster.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0d 09 16 08 16 1f 10 28 20 00 00 0a 09 16 08 1f 0f 1f 10 28 20 00 00 0a 06 08 6f 21 00 00 0a } //01 00 
		$a_03_1 = {13 05 12 05 fe 16 90 01 04 6f 90 01 04 72 90 01 04 28 90 01 04 0c 73 90 01 04 72 90 01 04 28 90 01 04 08 28 90 01 04 73 90 01 04 0d 09 6f 90 00 } //01 00 
		$a_00_2 = {77 00 69 00 6e 00 68 00 6f 00 73 00 74 00 65 00 72 00 } //01 00  winhoster
		$a_00_3 = {4e 00 70 00 66 00 20 00 4d 00 5a 00 4b 00 41 00 6a 00 6d 00 } //00 00  Npf MZKAjm
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}