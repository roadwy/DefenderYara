
rule TrojanDownloader_AndroidOS_SMSAgent_B_xp{
	meta:
		description = "TrojanDownloader:AndroidOS/SMSAgent.B!xp,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 47 41 4f 41 4e 44 52 4f 49 44 2e 43 4f 4d 2f 7a 6a 2f 32 30 31 35 31 31 30 36 2e 61 70 6b } //1 www.GAOANDROID.COM/zj/20151106.apk
		$a_00_1 = {39 31 2e 78 75 61 6e 67 75 61 77 6c 2e 63 6e 3a 38 30 39 31 2f 62 6d 62 6d 62 6d 2f 69 6e 66 6f 2f 67 65 74 63 70 69 6e 66 6f } //1 91.xuanguawl.cn:8091/bmbmbm/info/getcpinfo
		$a_00_2 = {4b 49 4c 4c 2d 2d 2d 61 70 70 44 6f 77 6e 6c 6f 61 64 } //1 KILL---appDownload
		$a_00_3 = {77 77 77 2e 7a 68 6a 6e 6e 2e 63 6f 6d 3a 32 30 30 30 32 2f 61 64 76 65 72 74 2f 61 70 70 2f 6c 69 73 74 } //2 www.zhjnn.com:20002/advert/app/list
		$a_00_4 = {78 69 78 69 2e 64 6a 31 31 31 2e 74 6f 70 3a 32 30 30 30 36 2f 53 6d 73 50 61 79 53 65 72 76 65 72 2f 73 6d 73 2f 73 64 6b 55 70 64 61 74 65 2f 69 6e 64 65 78 3f } //2 xixi.dj111.top:20006/SmsPayServer/sms/sdkUpdate/index?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=5
 
}