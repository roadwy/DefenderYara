
rule TrojanDownloader_BAT_Pstinb_AE_bit{
	meta:
		description = "TrojanDownloader:BAT/Pstinb.AE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 1d 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 00 } //01 00 
		$a_01_1 = {61 00 48 00 52 00 30 00 63 00 48 00 4d 00 36 00 4c 00 79 00 39 00 77 00 59 00 58 00 4e 00 30 00 5a 00 57 00 4a 00 70 00 62 00 69 00 35 00 6a 00 62 00 32 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}