
rule TrojanDownloader_Win32_Pacrpt_YA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Pacrpt.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 70 61 73 74 65 2e 65 65 2f 72 2f } //01 00  ://paste.ee/r/
		$a_01_1 = {22 79 72 61 6e 69 42 6f 54 67 6e 69 72 74 53 74 70 79 72 43 5c 6c 6c 64 2e 32 33 74 70 79 72 43 22 } //01 00  "yraniBoTgnirtStpyrC\lld.23tpyrC"
		$a_01_2 = {42 61 73 65 36 34 64 65 63 28 20 42 79 52 65 66 } //00 00  Base64dec( ByRef
	condition:
		any of ($a_*)
 
}