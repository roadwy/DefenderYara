
rule Trojan_AndroidOS_Fakeapp_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 6d 6f 62 69 6c 70 61 6b 6b 65 74 } //1 com/example/mobilpakket
		$a_01_1 = {77 65 7a 7a 78 2e 72 75 2f 61 70 6b 70 72 69 6c 3f 6b 65 79 77 6f 72 64 } //1 wezzx.ru/apkpril?keyword
		$a_01_2 = {73 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //1 setJavaScriptEnabled
		$a_01_3 = {6c 6f 61 64 55 72 6c } //1 loadUrl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}