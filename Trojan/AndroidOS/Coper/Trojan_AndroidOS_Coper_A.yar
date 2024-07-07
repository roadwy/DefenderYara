
rule Trojan_AndroidOS_Coper_A{
	meta:
		description = "Trojan:AndroidOS/Coper.A,SIGNATURE_TYPE_DEXHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_00_0 = {69 6e 6a 65 63 74 73 46 69 6c 6c 65 64 } //4 injectsFilled
		$a_00_1 = {69 6e 74 65 72 63 65 70 74 5f 6f 66 66 } //4 intercept_off
		$a_00_2 = {64 65 76 61 64 6d 69 6e 5f 63 6f 6e 66 69 72 6d } //4 devadmin_confirm
		$a_00_3 = {6c 61 73 74 5f 6b 65 79 6c 6f 67 5f 73 65 6e 64 } //4 last_keylog_send
		$a_00_4 = {52 45 53 5f 50 41 52 53 45 5f 54 41 53 4b 53 } //4 RES_PARSE_TASKS
		$a_00_5 = {45 58 43 5f 49 4e 4a 5f 41 43 54 } //4 EXC_INJ_ACT
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4+(#a_00_5  & 1)*4) >=24
 
}