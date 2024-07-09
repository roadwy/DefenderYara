
rule TrojanSpy_AndroidOS_SmsThief_AE_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 70 70 2e 69 73 6c 61 6e 64 74 72 61 76 65 6c } //1 com.app.islandtravel
		$a_00_1 = {61 70 70 2f 69 73 6c 61 6e 64 74 72 61 76 65 6c 2f 61 63 74 69 76 69 74 69 65 73 } //1 app/islandtravel/activities
		$a_00_2 = {79 65 6c 6c 6f 77 73 73 73 73 2e 6f 6e 6c 69 6e 65 } //1 yellowssss.online
		$a_00_3 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_03_4 = {61 70 69 5f 73 70 61 [0-20] 2f 61 70 69 5f 65 73 70 61 6e 6f 6c 2f 61 70 69 2e 70 68 70 3f 73 69 64 3d 25 31 24 73 26 73 6d 73 3d 25 32 24 73 } //1
		$a_00_5 = {6a 61 76 61 78 2f 69 6e 6a 65 63 74 2f 70 72 6f 76 69 64 65 72 3b } //1 javax/inject/provider;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}