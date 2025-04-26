
rule TrojanSpy_AndroidOS_SmsThief_AJ_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AJ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 6f 6e 61 69 6e 6f 72 6d 61 6e 2e 73 69 74 65 2f 53 4e 53 44 42 42 53 4a 4e 2f 49 53 53 41 53 44 53 } //1 yonainorman.site/SNSDBBSJN/ISSASDS
		$a_01_1 = {2f 63 6f 76 65 72 2e 68 74 6d 6c 3f 64 49 44 3d } //1 /cover.html?dID=
		$a_01_2 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 6b 6f 73 69 } //1 com.example.kosi
		$a_01_3 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getMessageBody
		$a_01_4 = {47 65 74 4d 6f 62 69 6c 65 44 6f 6d 61 69 6e } //1 GetMobileDomain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}