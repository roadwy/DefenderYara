
rule TrojanSpy_AndroidOS_SmsThief_AO_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.AO!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4d 53 50 72 61 70 74 69 } //1 SMSPrapti
		$a_01_1 = {67 65 6f 70 6f 2e 61 74 } //1 geopo.at
		$a_01_2 = {63 6f 6d 2f 63 6c 6f 75 64 67 61 6e 67 61 2f 61 6e 64 72 6f 69 64 2f 63 67 66 69 6e 64 65 72 } //1 com/cloudganga/android/cgfinder
		$a_01_3 = {54 52 41 43 4b 43 4d 44 } //1 TRACKCMD
		$a_01_4 = {70 61 72 73 65 53 4d 53 43 6d 64 } //1 parseSMSCmd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}