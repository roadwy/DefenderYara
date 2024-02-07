
rule TrojanDropper_AndroidOS_Sova_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Sova.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 73 45 6d 73 } //01 00  isEms
		$a_00_1 = {67 65 74 41 70 70 73 } //01 00  getApps
		$a_00_2 = {61 70 70 48 69 64 64 65 6e } //01 00  appHidden
		$a_00_3 = {75 70 64 61 74 65 69 6e 6a 65 63 74 73 } //01 00  updateinjects
		$a_00_4 = {32 66 61 63 74 6f 72 } //01 00  2factor
		$a_00_5 = {64 65 6c 65 74 65 63 6f 6d 6d 61 6e 64 } //01 00  deletecommand
		$a_00_6 = {69 6e 6a 65 63 74 6c 69 73 74 } //00 00  injectlist
	condition:
		any of ($a_*)
 
}