
rule TrojanSpy_AndroidOS_Goatrat_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Goatrat.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 72 76 2e 79 61 6b 75 7a 61 63 68 65 63 6b 65 72 73 2e 63 6f 6d 2f 77 65 62 2d 61 64 6d 69 6e 2f } //1 srv.yakuzacheckers.com/web-admin/
		$a_01_1 = {67 6f 61 74 72 61 74 } //1 goatrat
		$a_01_2 = {53 63 72 65 65 6e 53 68 61 72 69 6e 67 53 65 72 76 69 63 65 } //1 ScreenSharingService
		$a_01_3 = {2f 72 74 70 2d 77 65 62 2d 61 64 6d 69 6e 2f } //1 /rtp-web-admin/
		$a_01_4 = {44 69 73 63 6f 72 64 57 65 62 68 6f 6f 6b } //1 DiscordWebhook
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}