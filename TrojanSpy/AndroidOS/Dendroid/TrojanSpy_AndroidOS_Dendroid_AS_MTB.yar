
rule TrojanSpy_AndroidOS_Dendroid_AS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dendroid.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 6c 65 74 65 63 61 6c 6c 6c 6f 67 6e 75 6d 62 65 72 } //01 00  deletecalllognumber
		$a_00_1 = {67 65 74 63 61 6c 6c 68 69 73 74 6f 72 79 } //01 00  getcallhistory
		$a_00_2 = {67 65 74 73 65 6e 74 73 6d 73 } //01 00  getsentsms
		$a_00_3 = {52 65 63 6f 72 64 43 61 6c 6c 73 } //01 00  RecordCalls
		$a_00_4 = {53 63 72 65 65 6e 20 4f 66 66 20 52 75 6e 20 53 65 72 76 69 63 65 } //01 00  Screen Off Run Service
		$a_00_5 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f 75 70 64 61 74 65 2e 61 70 6b } //00 00  /mnt/sdcard/Download/update.apk
		$a_00_6 = {5d 04 00 00 8f } //87 04 
	condition:
		any of ($a_*)
 
}