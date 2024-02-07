
rule MonitoringTool_AndroidOS_Reptilic_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Reptilic.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 61 6b 65 41 63 74 69 76 69 74 79 } //01 00  FakeActivity
		$a_01_1 = {73 65 6e 64 5f 6d 65 64 69 61 5f 6f 6e 6c 79 5f 77 69 66 69 } //01 00  send_media_only_wifi
		$a_01_2 = {76 69 70 66 69 6c 65 2e 75 7a 2f 66 73 66 6c 2f 38 4d 39 39 69 48 77 78 77 6f 77 4e 71 51 72 } //01 00  vipfile.uz/fsfl/8M99iHwxwowNqQr
		$a_01_3 = {73 6d 73 5f 63 6f 64 65 5f 77 6f 72 64 } //00 00  sms_code_word
	condition:
		any of ($a_*)
 
}