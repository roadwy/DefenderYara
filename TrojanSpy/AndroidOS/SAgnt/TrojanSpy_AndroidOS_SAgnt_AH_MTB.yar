
rule TrojanSpy_AndroidOS_SAgnt_AH_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AH!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 70 72 61 67 6d 61 2f 41 63 74 69 76 69 74 79 52 75 6e } //1 com/example/pragma/ActivityRun
		$a_01_1 = {2e 41 64 6d 69 6e 55 72 6c 2e } //1 .AdminUrl.
		$a_01_2 = {41 50 50 61 64 69 2d 74 65 78 74 } //1 APPadi-text
		$a_01_3 = {69 6e 4b 65 79 67 75 61 72 64 52 65 73 74 72 69 63 74 65 64 49 6e 70 75 74 4d 6f 64 65 } //1 inKeyguardRestrictedInputMode
		$a_01_4 = {4c 6f 67 53 4d 53 } //1 LogSMS
		$a_01_5 = {70 72 61 67 6d 61 5f 73 74 61 72 74 } //1 pragma_start
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}