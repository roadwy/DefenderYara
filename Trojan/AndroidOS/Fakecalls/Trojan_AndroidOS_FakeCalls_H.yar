
rule Trojan_AndroidOS_FakeCalls_H{
	meta:
		description = "Trojan:AndroidOS/FakeCalls.H,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6d 53 6d 73 41 63 74 69 76 69 74 79 } //2 ComSmsActivity
		$a_00_1 = {43 41 4c 4c 5f 53 4f 55 52 43 45 5f 46 4f 52 57 41 52 44 49 4e 47 5f 48 41 4e 47 5f 55 50 } //2 CALL_SOURCE_FORWARDING_HANG_UP
		$a_00_2 = {4b 45 59 5f 49 53 5f 46 4f 52 43 45 44 5f 43 41 4c 4c } //2 KEY_IS_FORCED_CALL
		$a_00_3 = {4b 45 59 5f 43 4c 4f 53 45 5f 54 43 41 4c 4c 5f 41 4c 45 52 54 5f 57 49 4e 44 4f 57 } //2 KEY_CLOSE_TCALL_ALERT_WINDOW
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}