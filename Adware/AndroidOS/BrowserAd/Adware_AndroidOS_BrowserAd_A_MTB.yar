
rule Adware_AndroidOS_BrowserAd_A_MTB{
	meta:
		description = "Adware:AndroidOS/BrowserAd.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 4f 6e 63 6c 69 63 6b 4c 69 6e 6b } //1 openOnclickLink
		$a_01_1 = {64 65 76 2f 61 70 70 6c 61 62 7a 2f 61 64 2f 61 63 74 69 76 69 74 79 2f 54 72 61 6e 73 70 61 72 65 6e 74 43 6c 69 63 6b 65 72 } //1 dev/applabz/ad/activity/TransparentClicker
		$a_01_2 = {22 00 92 24 1a 01 20 b5 70 20 f9 df 10 00 60 01 dc bd 54 d1 dd bd 54 12 9e 76 6e 20 04 e0 20 00 6e 10 13 e0 00 00 0c 00 6e 10 9a 08 01 00 0c 02 1a 03 07 8d 71 20 bb e5 32 00 60 03 44 10 13 04 00 20 12 05 12 16 1a 07 4c df 13 08 1d 00 1a 09 c4 b6 12 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}