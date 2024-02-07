
rule TrojanSpy_AndroidOS_GlodEagl_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GlodEagl.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 2e 35 32 76 70 65 6e 2e 6e 65 74 } //01 00  ht.52vpen.net
		$a_01_1 = {61 70 69 2e 68 61 77 61 72 2e 63 6e } //01 00  api.hawar.cn
		$a_01_2 = {61 70 69 2e 78 6f 68 2e 63 6e } //01 00  api.xoh.cn
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 70 6c 75 67 69 6e 2e 61 70 6b } //01 00  /system/app/plugin.apk
		$a_01_4 = {63 6f 6d 2f 63 61 6c 6c 72 65 63 6f 72 64 65 72 2f 73 65 72 76 69 63 65 } //01 00  com/callrecorder/service
		$a_01_5 = {64 65 66 61 75 6c 74 54 72 6f 6a 61 6e } //00 00  defaultTrojan
	condition:
		any of ($a_*)
 
}