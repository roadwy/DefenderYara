
rule Trojan_BAT_CoinMiner_PJ_bit{
	meta:
		description = "Trojan:BAT/CoinMiner.PJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 0f 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 1d 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 07 52 00 75 00 6e 00 } //01 00  ༀWindowsᴀCurrentVersion܀Run
		$a_01_1 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 } //01 00  pastebin.com/raw/
		$a_01_2 = {2e 00 6d 00 69 00 78 00 74 00 61 00 70 00 65 00 2e 00 6d 00 6f 00 65 00 2f 00 } //01 00  .mixtape.moe/
		$a_01_3 = {2e 00 70 00 6f 00 6d 00 66 00 2e 00 63 00 61 00 74 00 2f 00 } //00 00  .pomf.cat/
	condition:
		any of ($a_*)
 
}