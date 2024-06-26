
rule Trojan_BAT_Downloader_INKT_MTB{
	meta:
		description = "Trojan:BAT/Downloader.INKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 31 63 61 38 34 63 33 35 2d 63 63 38 64 2d 34 33 32 33 2d 61 32 66 64 2d 37 61 37 61 33 38 35 37 31 66 66 66 } //01 00  $1ca84c35-cc8d-4323-a2fd-7a7a38571fff
		$a_01_1 = {52 65 61 64 49 6e 74 65 72 63 65 70 74 6f 72 } //01 00  ReadInterceptor
		$a_01_2 = {43 72 65 61 74 65 4d 61 70 70 65 72 } //01 00  CreateMapper
		$a_01_3 = {50 72 65 70 61 72 65 4d 61 70 70 65 72 } //01 00  PrepareMapper
		$a_01_4 = {67 65 74 5f 43 7a 73 6e 71 64 63 78 } //01 00  get_Czsnqdcx
		$a_01_5 = {44 65 73 74 72 6f 79 4d 61 70 70 65 72 } //01 00  DestroyMapper
		$a_01_6 = {44 69 73 61 62 6c 65 4d 61 70 70 65 72 } //01 00  DisableMapper
		$a_01_7 = {52 75 6e 4d 61 70 70 65 72 } //00 00  RunMapper
	condition:
		any of ($a_*)
 
}