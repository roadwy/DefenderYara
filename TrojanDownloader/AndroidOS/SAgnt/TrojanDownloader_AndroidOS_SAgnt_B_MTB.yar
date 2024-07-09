
rule TrojanDownloader_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6c 5f 61 70 70 75 70 64 61 74 65 } //1 cl_appupdate
		$a_00_1 = {2f 41 70 70 55 70 64 61 74 65 45 78 61 6d 70 6c 65 2e 74 78 74 } //1 /AppUpdateExample.txt
		$a_00_2 = {5f 75 70 64 61 74 65 5f 75 70 64 61 74 65 63 6f 6d 70 6c 65 74 65 } //1 _update_updatecomplete
		$a_00_3 = {69 6e 73 74 61 6c 6c 5f 6e 6f 6e 5f 6d 61 72 6b 65 74 5f 61 70 70 73 } //1 install_non_market_apps
		$a_00_4 = {5f 73 6e 65 77 76 65 72 61 70 6b } //1 _snewverapk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_AndroidOS_SAgnt_B_MTB_2{
	meta:
		description = "TrojanDownloader:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 02 0b 00 38 02 ?? 00 22 04 ?? 00 70 10 ?? ?? 04 00 13 02 00 02 71 30 ?? ?? 0b 02 0c 02 5b 42 13 00 d0 00 00 02 d8 00 00 04 61 06 0f 00 71 20 ?? ?? 0b 00 0a 02 81 28 bd 86 5a 46 14 00 d8 00 00 04 61 06 0f 00 71 20 ?? ?? 0b 00 0a 02 81 28 bd 86 5a 46 15 00 d8 00 00 04 54 42 13 00 1a 05 ?? 00 6e 20 ?? ?? 52 00 0a 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}