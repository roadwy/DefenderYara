
rule Trojan_AndroidOS_GingerMaster_B{
	meta:
		description = "Trojan:AndroidOS/GingerMaster.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 20 53 64 43 61 72 64 2c 20 43 61 6e 27 74 20 52 75 6e 21 } //1 No SdCard, Can't Run!
		$a_01_1 = {67 61 6d 65 5f 73 65 72 76 69 63 65 5f 64 6f 77 6e 6c 6f 61 64 64 62 2e 64 62 } //1 game_service_downloaddb.db
		$a_03_2 = {63 6c 69 65 6e 74 2e 90 02 09 2e 63 6f 6d 2f 72 65 70 6f 72 74 2f 72 65 74 75 72 6e 5f 61 6c 65 72 74 2e 64 6f 90 00 } //1
		$a_01_3 = {70 6e 69 20 4f 4e 20 67 61 6d 65 5f 70 61 63 6b 61 67 65 20 28 70 61 63 6b 61 67 65 5f 6e 61 6d 65 29 } //1 pni ON game_package (package_name)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}