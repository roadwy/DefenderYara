
rule Adware_AndroidOS_Dnotua_A_MTB{
	meta:
		description = "Adware:AndroidOS/Dnotua.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 77 65 62 68 35 2f 63 6f 64 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  com/webh5/code/MainActivity
		$a_01_1 = {2f 55 72 6c 4f 70 65 6e 54 6f 6f 6c } //01 00  /UrlOpenTool
		$a_01_2 = {73 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //01 00  setJavaScriptEnabled
		$a_01_3 = {73 65 74 44 6f 6d 53 74 6f 72 61 67 65 45 6e 61 62 6c 65 64 } //01 00  setDomStorageEnabled
		$a_01_4 = {73 68 6f 75 6c 64 4f 76 65 72 72 69 64 65 55 72 6c 4c 6f 61 64 69 6e 67 } //01 00  shouldOverrideUrlLoading
		$a_01_5 = {63 61 6e 47 6f 42 61 63 6b } //00 00  canGoBack
	condition:
		any of ($a_*)
 
}