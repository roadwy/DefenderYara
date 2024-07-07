
rule TrojanDownloader_BAT_MSILZilla_RDB_MTB{
	meta:
		description = "TrojanDownloader:BAT/MSILZilla.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 30 62 35 33 38 63 64 2d 64 37 62 63 2d 34 64 64 32 2d 61 66 39 31 2d 34 65 33 35 61 38 32 30 63 32 32 31 } //1 e0b538cd-d7bc-4dd2-af91-4e35a820c221
		$a_01_1 = {4c 69 6d 75 78 54 6f 6f 6c } //1 LimuxTool
		$a_01_2 = {45 00 69 00 69 00 67 00 7a 00 73 00 } //1 Eiigzs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}