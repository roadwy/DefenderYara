
rule TrojanDownloader_BAT_Fakare_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Fakare.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 64 00 64 00 72 00 74 00 6a 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5f 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 76 00 62 00 73 00 } //01 00 
		$a_01_2 = {73 76 63 68 6f 73 74 69 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}