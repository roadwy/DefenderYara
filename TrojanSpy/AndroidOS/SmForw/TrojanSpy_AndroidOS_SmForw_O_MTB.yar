
rule TrojanSpy_AndroidOS_SmForw_O_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 64 4d 79 57 65 62 41 63 74 69 76 69 74 79 } //01 00  edMyWebActivity
		$a_00_1 = {67 64 43 61 6e 63 65 6c 4e 6f 74 69 63 65 53 65 72 76 69 63 65 } //01 00  gdCancelNoticeService
		$a_00_2 = {64 67 4d 61 69 6e 53 65 72 76 69 63 65 } //01 00  dgMainService
		$a_00_3 = {67 68 73 4d 79 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00  ghsMyApplication
	condition:
		any of ($a_*)
 
}