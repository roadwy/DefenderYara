
rule Trojan_AndroidOS_HiddenApp_C_MTB{
	meta:
		description = "Trojan:AndroidOS/HiddenApp.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6d 65 6d 62 65 72 73 67 69 72 2f 69 69 61 70 70 73 } //01 00  com/membersgir/iiapps
		$a_00_1 = {68 69 64 64 65 6e 41 70 70 49 63 6f 6e } //01 00  hiddenAppIcon
		$a_00_2 = {52 65 73 75 6d 61 62 6c 65 53 75 62 5f 53 65 72 76 69 63 65 5f 53 74 61 72 74 } //01 00  ResumableSub_Service_Start
		$a_00_3 = {63 61 6e 4f 76 65 72 44 72 61 77 4f 74 68 65 72 41 70 70 73 } //01 00  canOverDrawOtherApps
		$a_00_4 = {5f 70 6f 70 75 70 74 65 6c 65 67 72 61 6d } //01 00  _popuptelegram
		$a_00_5 = {69 69 61 70 70 73 2f 64 6e 6f 72 6d 61 6c } //00 00  iiapps/dnormal
	condition:
		any of ($a_*)
 
}