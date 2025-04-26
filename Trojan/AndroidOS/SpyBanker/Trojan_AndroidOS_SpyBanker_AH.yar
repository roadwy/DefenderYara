
rule Trojan_AndroidOS_SpyBanker_AH{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.AH,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 4d 61 6c 77 61 72 65 } //1 setMalware
		$a_01_1 = {70 72 61 74 69 6e 67 3d } //1 prating=
		$a_01_2 = {41 20 6d 65 73 73 61 67 65 20 61 62 6f 75 74 20 73 6f 6d 65 74 68 69 6e 67 20 77 65 69 72 64 } //1 A message about something weird
		$a_01_3 = {74 65 78 74 5f 73 6d 73 5f 70 65 72 6d 69 73 73 69 6f 6e 5f 72 65 71 75 69 72 65 64 } //1 text_sms_permission_required
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}