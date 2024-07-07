
rule Trojan_AndroidOS_SpyAgent_C{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.C,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 6c 61 74 65 5f 70 68 69 73 68 69 6e 67 5f 75 72 6c } //1 template_phishing_url
		$a_01_1 = {70 68 69 73 68 69 6e 67 5f 61 70 70 6e 61 6d 65 } //1 phishing_appname
		$a_01_2 = {73 6d 73 6c 69 73 74 } //1 smslist
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}