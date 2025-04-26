
rule TrojanSpy_AndroidOS_Cookiethief_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Cookiethief.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {79 6f 75 7a 69 63 68 65 6e 67 2e 6e 65 74 2f 61 70 69 2f 72 65 73 6f 75 72 63 65 2f 75 70 6c 6f 61 64 46 61 63 65 62 6f 6f 6b 43 6f 6f 6b 69 65 } //2 youzicheng.net/api/resource/uploadFacebookCookie
		$a_00_1 = {2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 66 61 63 65 62 6f 6f 6b 2e 6b 61 74 61 6e 61 2f 61 70 70 5f 77 65 62 76 69 65 77 2f 43 6f 6f 6b 69 65 73 } //1 /data/data/com.facebook.katana/app_webview/Cookies
		$a_00_2 = {2f 66 69 6c 65 73 2f 43 6f 6f 6b 69 65 73 43 68 72 6f 6d 65 } //1 /files/CookiesChrome
		$a_00_3 = {63 70 20 25 73 20 2f 64 61 74 61 2f 64 61 74 61 2f 25 73 2f 66 69 6c 65 73 2f 25 73 } //1 cp %s /data/data/%s/files/%s
		$a_00_4 = {69 63 6f 6e 48 69 64 65 } //1 iconHide
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}