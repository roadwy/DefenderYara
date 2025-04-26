
rule Backdoor_BAT_Corinrat_A{
	meta:
		description = "Backdoor:BAT/Corinrat.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {7c 00 43 00 6f 00 72 00 69 00 6e 00 67 00 61 00 7c 00 } //10 |Coringa|
		$a_00_1 = {41 00 75 00 64 00 69 00 6f 00 20 00 43 00 61 00 70 00 74 00 75 00 72 00 65 00 } //1 Audio Capture
		$a_00_2 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //1 get_Computer
		$a_00_3 = {67 65 74 5f 41 70 70 6c 69 63 61 74 69 6f 6e } //1 get_Application
		$a_00_4 = {67 65 74 5f 55 73 65 72 } //1 get_User
		$a_00_5 = {67 65 74 5f 46 6f 72 6d 73 } //1 get_Forms
		$a_00_6 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //1 get_WebServices
		$a_00_7 = {67 65 74 5f 43 6c 69 65 6e 74 } //1 get_Client
		$a_00_8 = {67 65 74 5f 44 72 69 76 65 54 79 70 65 } //1 get_DriveType
		$a_00_9 = {67 65 74 5f 4a 70 65 67 } //1 get_Jpeg
		$a_00_10 = {67 65 74 5f 43 6f 6e 6e 65 63 74 65 64 } //1 get_Connected
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=12
 
}