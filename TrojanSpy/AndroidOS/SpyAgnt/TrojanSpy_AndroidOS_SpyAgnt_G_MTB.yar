
rule TrojanSpy_AndroidOS_SpyAgnt_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 72 65 63 65 69 76 65 72 2f 41 75 74 6f 53 74 61 72 74 3b } //1 /receiver/AutoStart;
		$a_00_1 = {2f 61 63 74 69 76 69 74 69 65 73 2f 4c 6f 63 6b 4d 65 4e 6f 77 41 63 74 69 76 69 74 79 3b } //1 /activities/LockMeNowActivity;
		$a_00_2 = {2f 73 65 72 76 69 63 65 73 2f 48 69 64 65 41 70 70 49 63 6f 6e 53 65 72 76 69 63 65 3b } //1 /services/HideAppIconService;
		$a_00_3 = {73 65 72 76 69 63 65 73 2f 73 63 72 65 65 6e 2f 53 63 72 65 65 6e 73 68 6f 74 53 65 72 76 69 63 65 } //1 services/screen/ScreenshotService
		$a_00_4 = {2f 6b 65 79 6c 6f 67 67 65 72 2e 74 78 74 } //1 /keylogger.txt
		$a_00_5 = {2f 73 63 68 65 64 75 6c 65 64 5f 72 65 63 6f 72 64 65 72 73 2e 74 78 74 } //1 /scheduled_recorders.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}