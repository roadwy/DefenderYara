
rule TrojanDownloader_BAT_Genmaldow_N{
	meta:
		description = "TrojanDownloader:BAT/Genmaldow.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 } //01 00 
		$a_01_1 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58 } //01 00 
		$a_01_2 = {69 64 6f 74 6b 6e 6f 77 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}