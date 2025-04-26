
rule Trojan_AndroidOS_SmsThief_Q{
	meta:
		description = "Trojan:AndroidOS/SmsThief.Q,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 63 63 6f 75 6e 74 20 41 6e 64 20 4d 6f 62 69 6c 65 20 4e 75 6d 62 65 72 20 56 65 72 69 66 79 20 53 75 63 65 73 73 66 75 6c 6c 79 2e 2e } //1 Account And Mobile Number Verify Sucessfully..
		$a_01_1 = {53 4d 53 20 62 6f 64 79 20 66 6f 72 77 61 72 64 65 64 20 74 6f } //1 SMS body forwarded to
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_AndroidOS_SmsThief_Q_2{
	meta:
		description = "Trojan:AndroidOS/SmsThief.Q,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 6f 62 6f 74 73 6d 73 73 65 6e 74 2e 70 68 70 3f 69 61 6d 3d } //2 robotsmssent.php?iam=
		$a_01_1 = {48 69 6c 74 5f 52 6f 62 6f 74 53 4d 53 41 70 70 } //2 Hilt_RobotSMSApp
		$a_01_2 = {44 61 67 67 65 72 52 6f 62 6f 74 53 4d 53 41 70 70 5f 48 69 6c 74 43 6f 6d 70 6f 6e 65 6e 74 73 5f 53 69 6e 67 6c 65 74 6f 6e 43 } //2 DaggerRobotSMSApp_HiltComponents_SingletonC
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}