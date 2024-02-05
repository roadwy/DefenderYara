
rule TrojanDownloader_Win32_TinyBanker_GZN_MTB{
	meta:
		description = "TrojanDownloader:Win32/TinyBanker.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 9c 24 db 01 00 00 88 cf 28 df 66 89 c6 66 21 f2 66 89 94 24 90 01 04 88 bc 24 90 01 04 8b 84 24 90 01 04 8b 4c 24 2c 01 c8 89 84 24 90 01 04 e9 3d ff ff ff 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 42 72 65 61 6b } //01 00 
		$a_01_2 = {73 72 61 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}