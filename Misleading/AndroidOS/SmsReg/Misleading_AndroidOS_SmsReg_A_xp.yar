
rule Misleading_AndroidOS_SmsReg_A_xp{
	meta:
		description = "Misleading:AndroidOS/SmsReg.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {31 30 2e 32 33 35 2e 31 34 38 2e 39 2f 6d 69 64 64 6c 65 2f 6d 79 70 61 67 65 6f 72 64 65 72 2e 6a 73 70 } //1 10.235.148.9/middle/mypageorder.jsp
		$a_00_1 = {44 43 41 67 65 6e 74 5f 6f 6e 4b 69 6c 6c 50 72 6f 63 65 73 73 4f 72 45 78 69 74 } //1 DCAgent_onKillProcessOrExit
		$a_00_2 = {61 70 69 2e 64 6a 31 31 31 2e 74 6f 70 3a 32 30 30 30 36 2f 53 6d 73 50 61 79 53 65 72 76 65 72 2f 67 65 74 4d 65 73 73 61 67 65 2f 67 65 74 53 44 4b 4d 65 73 73 61 67 65 4a 73 6f 6e } //1 api.dj111.top:20006/SmsPayServer/getMessage/getSDKMessageJson
		$a_00_3 = {41 6e 64 72 6f 69 64 2f 64 61 74 61 2f 63 6f 6d 2e 64 6f 6f 72 2e 70 61 79 2e 61 70 70 2f } //1 Android/data/com.door.pay.app/
		$a_00_4 = {77 77 77 2e 7a 68 6a 6e 6e 2e 63 6f 6d 3a 32 30 30 30 32 2f 61 64 76 65 72 74 2f 69 6e 66 6f 2f 75 73 65 72 41 63 74 69 6f 6e 73 3f 61 70 70 49 64 3d } //1 www.zhjnn.com:20002/advert/info/userActions?appId=
		$a_00_5 = {73 65 74 4f 6e 4b 65 79 4c 69 73 74 65 6e 65 72 } //1 setOnKeyListener
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}