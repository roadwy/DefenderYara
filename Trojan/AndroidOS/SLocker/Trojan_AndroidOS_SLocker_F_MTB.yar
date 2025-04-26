
rule Trojan_AndroidOS_SLocker_F_MTB{
	meta:
		description = "Trojan:AndroidOS/SLocker.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {51 51 3a 31 35 30 30 30 34 36 34 36 31 } //1 QQ:1500046461
		$a_01_1 = {51 51 4d 61 69 6c 3a 31 35 30 30 30 34 36 34 36 31 } //1 QQMail:1500046461
		$a_01_2 = {69 6e 63 6f 6d 69 6e 67 5f 6e 75 6d 62 65 72 } //1 incoming_number
		$a_01_3 = {69 73 53 65 72 76 69 63 65 52 75 6e } //1 isServiceRun
		$a_01_4 = {6c 6f 67 63 61 74 20 2d 76 20 74 68 72 65 61 64 74 69 6d 65 } //1 logcat -v threadtime
		$a_00_5 = {63 6f 6d 2e 73 2e 63 2e 6a 73 } //1 com.s.c.js
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}