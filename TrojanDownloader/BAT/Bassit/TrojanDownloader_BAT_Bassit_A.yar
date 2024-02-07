
rule TrojanDownloader_BAT_Bassit_A{
	meta:
		description = "TrojanDownloader:BAT/Bassit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {7c 6b 61 6b 61 72 6f 74 74 6f 7c 90 02 80 2f 2f 3a 90 02 01 70 74 74 68 90 00 } //01 00 
		$a_03_1 = {74 00 65 00 6d 00 70 00 90 01 02 73 00 74 00 61 00 72 00 90 01 02 5c 00 90 01 02 44 00 41 00 54 00 41 00 90 01 02 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 90 00 } //01 00 
		$a_01_2 = {5c 6b 61 6b 61 72 6f 74 74 6f 5c 44 65 73 6b 74 6f 70 5c 6e 65 77 20 73 65 72 76 65 72 5c 62 75 69 6c 64 65 72 5c } //00 00  \kakarotto\Desktop\new server\builder\
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}