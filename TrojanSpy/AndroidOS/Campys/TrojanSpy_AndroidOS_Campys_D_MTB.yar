
rule TrojanSpy_AndroidOS_Campys_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Campys.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 61 72 64 69 73 2f 62 6f 6f 6b 5f 6e 61 6d 65 2f 6c 69 73 74 } //01 00  pardis/book_name/list
		$a_01_1 = {72 75 6e 41 66 74 65 72 53 63 72 65 65 6e 4f 6e } //01 00  runAfterScreenOn
		$a_01_2 = {53 63 72 65 65 6e 43 6f 6e 74 72 6f 6c } //01 00  ScreenControl
		$a_01_3 = {46 69 6c 65 55 70 6c 6f 61 64 54 61 73 6b } //01 00  FileUploadTask
		$a_01_4 = {52 65 63 6f 72 64 41 75 64 69 6f 54 61 73 6b } //00 00  RecordAudioTask
	condition:
		any of ($a_*)
 
}