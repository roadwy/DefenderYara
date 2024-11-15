
rule TrojanSpy_AndroidOS_SoumniBot_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SoumniBot.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 72 6f 63 2f 70 6f 73 74 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/proc/post/MainActivity
		$a_01_1 = {49 4e 49 54 20 53 45 4e 53 5f 53 4d 53 5f 56 41 4c } //1 INIT SENS_SMS_VAL
		$a_01_2 = {53 65 6e 64 54 69 6d 65 44 69 66 66 41 6c 61 72 6d } //1 SendTimeDiffAlarm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}