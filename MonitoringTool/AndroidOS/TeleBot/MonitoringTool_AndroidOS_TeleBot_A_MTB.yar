
rule MonitoringTool_AndroidOS_TeleBot_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/TeleBot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_00_0 = {42 6f 74 55 74 69 6c 73 4b 74 } //1 BotUtilsKt
		$a_00_1 = {72 65 71 75 65 73 74 41 63 63 65 73 73 54 6f 53 63 72 65 65 6e 73 68 6f 74 73 } //1 requestAccessToScreenshots
		$a_00_2 = {63 6f 6d 2e 72 65 6d 6f 74 65 62 6f 74 2e 61 6e 64 72 6f 69 64 2e 70 72 65 73 65 6e 74 61 74 69 6f 6e } //10 com.remotebot.android.presentation
		$a_00_3 = {74 74 70 73 3a 2f 2f 72 65 6d 6f 74 65 2d 62 6f 74 2e 63 6f 6d 2f } //1 ttps://remote-bot.com/
		$a_00_4 = {73 65 6e 64 50 68 6f 74 6f } //1 sendPhoto
		$a_00_5 = {73 65 6e 64 54 65 78 74 } //1 sendText
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=14
 
}