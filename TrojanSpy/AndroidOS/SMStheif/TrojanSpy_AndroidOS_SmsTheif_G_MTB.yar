
rule TrojanSpy_AndroidOS_SmsTheif_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsTheif.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6c 73 74 5f 73 72 76 63 74 72 6c } //01 00  rlst_srvctrl
		$a_01_1 = {63 6e 66 69 6e 66 6f 5f 63 6d 64 5f 6b 65 79 77 6f 72 64 } //01 00  cnfinfo_cmd_keyword
		$a_01_2 = {72 65 6d 69 6e 66 6f 5f 63 6f 75 6e 74 3d } //01 00  reminfo_count=
		$a_01_3 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //01 00  getOriginatingAddress
		$a_01_4 = {63 6f 6e 66 69 67 5f 66 65 65 5f 69 74 65 6d } //01 00  config_fee_item
		$a_01_5 = {63 6f 6e 66 69 67 5f 66 65 65 5f 77 61 70 } //00 00  config_fee_wap
	condition:
		any of ($a_*)
 
}