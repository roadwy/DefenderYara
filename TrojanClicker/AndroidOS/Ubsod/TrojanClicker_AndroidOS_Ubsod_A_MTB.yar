
rule TrojanClicker_AndroidOS_Ubsod_A_MTB{
	meta:
		description = "TrojanClicker:AndroidOS/Ubsod.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 6f 70 4d 65 41 64 48 6f 6c 64 65 72 } //1 LoopMeAdHolder
		$a_01_1 = {67 65 74 43 65 6c 6c 4c 6f 63 61 74 69 6f 6e } //1 getCellLocation
		$a_01_2 = {64 69 61 6c 6f 67 5f 64 6f 77 6e 6c 6f 61 64 5f 61 63 74 69 76 69 74 79 5f 74 69 74 6c 65 } //1 dialog_download_activity_title
		$a_01_3 = {41 64 41 63 74 69 76 69 74 79 } //1 AdActivity
		$a_01_4 = {6c 6f 63 6b 4e 6f 77 } //1 lockNow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}