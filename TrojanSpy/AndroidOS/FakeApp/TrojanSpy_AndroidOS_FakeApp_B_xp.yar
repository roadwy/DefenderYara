
rule TrojanSpy_AndroidOS_FakeApp_B_xp{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 64 61 74 2f 61 38 61 6e 64 6f 73 65 72 76 65 72 78 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/example/dat/a8andoserverx/MainActivity
		$a_00_1 = {47 78 65 78 74 73 78 6d 73 } //1 Gxextsxms
		$a_00_2 = {47 65 74 63 6f 6e 73 74 61 63 74 78 } //1 Getconstactx
		$a_00_3 = {73 63 72 65 58 6d 65 78 } //1 screXmex
		$a_00_4 = {68 6f 38 6d 61 69 6c 2e 64 64 6e 73 2e 6e 65 74 } //1 ho8mail.ddns.net
		$a_00_5 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 20 } //1 /system/bin/screencap -p 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}