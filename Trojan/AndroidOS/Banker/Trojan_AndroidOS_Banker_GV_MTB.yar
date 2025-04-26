
rule Trojan_AndroidOS_Banker_GV_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 77 69 74 63 68 4f 62 6a 65 63 74 54 6f 49 6e 74 } //1 switchObjectToInt
		$a_01_1 = {73 65 6e 64 5f 6e 6f 74 69 66 79 } //1 send_notify
		$a_01_2 = {75 70 5f 61 70 70 } //1 up_app
		$a_01_3 = {72 75 6e 5f 70 61 74 74 65 72 6e } //1 run_pattern
		$a_01_4 = {72 75 6e 5f 74 65 6c } //1 run_tel
		$a_01_5 = {74 6f 75 63 68 5f 63 6c 69 63 6b } //1 touch_click
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}