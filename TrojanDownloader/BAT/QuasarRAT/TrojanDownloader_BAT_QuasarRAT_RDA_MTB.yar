
rule TrojanDownloader_BAT_QuasarRAT_RDA_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 37 36 32 38 35 66 35 2d 36 30 61 64 2d 34 37 34 32 2d 61 65 32 64 2d 65 36 36 36 31 33 31 36 61 62 65 31 } //01 00  c76285f5-60ad-4742-ae2d-e6661316abe1
		$a_01_1 = {4b 79 71 72 65 78 50 72 65 } //01 00  KyqrexPre
		$a_01_2 = {63 34 31 35 32 61 61 65 2d 34 36 65 36 2d 34 38 30 61 2d 38 30 31 66 2d 35 35 34 31 66 33 34 30 38 66 64 33 } //00 00  c4152aae-46e6-480a-801f-5541f3408fd3
	condition:
		any of ($a_*)
 
}