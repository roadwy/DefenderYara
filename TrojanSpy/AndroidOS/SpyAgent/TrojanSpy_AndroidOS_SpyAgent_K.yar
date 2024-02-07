
rule TrojanSpy_AndroidOS_SpyAgent_K{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.K,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 4c 6f 63 61 6c 41 6c 62 75 6d 4c 69 73 74 } //01 00  getLocalAlbumList
		$a_00_1 = {2f 68 6f 6d 65 2f 68 65 6c 70 } //01 00  /home/help
		$a_00_2 = {67 65 74 44 65 76 69 63 65 53 65 72 69 61 6c 4d 44 35 } //01 00  getDeviceSerialMD5
		$a_00_3 = {7a 63 61 74 70 78 47 65 6e 74 72 69 66 69 } //00 00  zcatpxGentrifi
	condition:
		any of ($a_*)
 
}