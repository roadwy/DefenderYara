
rule TrojanDownloader_AndroidOS_DownAgent_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/DownAgent.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 68 61 6c 65 79 63 6f 6d 6d 65 74 2f 64 61 72 6b 77 65 62 2f 70 6c 61 79 73 74 6f 72 65 2f } //02 00  Lcom/haleycommet/darkweb/playstore/
		$a_00_1 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //01 00  cdn.discordapp.com/attachments/
		$a_00_2 = {2f 55 70 64 61 74 65 2e 61 70 6b } //01 00  /Update.apk
		$a_00_3 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 70 61 63 6b 61 67 65 69 6e 73 74 61 6c 6c 65 72 3a 69 64 2f 70 65 72 6d 69 73 73 69 6f 6e 5f 61 6c 6c 6f 77 5f 62 75 74 74 6f 6e } //01 00  com.android.packageinstaller:id/permission_allow_button
		$a_00_4 = {2f 50 65 72 6d 41 63 74 3b } //00 00  /PermAct;
		$a_00_5 = {5d 04 00 } //00 c6 
	condition:
		any of ($a_*)
 
}