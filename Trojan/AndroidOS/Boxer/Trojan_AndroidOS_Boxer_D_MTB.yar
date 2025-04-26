
rule Trojan_AndroidOS_Boxer_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Boxer.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 2f 73 6d 73 62 6f 78 } //1 data/smsbox
		$a_01_1 = {53 4d 53 53 65 6e 64 65 72 } //1 SMSSender
		$a_01_2 = {61 6e 64 72 6f 69 64 62 6f 78 2e 73 75 2f 73 6d 73 5f 72 73 73 } //1 androidbox.su/sms_rss
		$a_01_3 = {64 61 74 61 2e 78 6d 6c } //1 data.xml
		$a_01_4 = {73 63 65 6e 65 5f 73 6d 73 6c 69 73 74 } //1 scene_smslist
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}