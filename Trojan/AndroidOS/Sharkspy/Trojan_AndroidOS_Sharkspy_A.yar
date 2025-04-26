
rule Trojan_AndroidOS_Sharkspy_A{
	meta:
		description = "Trojan:AndroidOS/Sharkspy.A,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 5f 52 61 6e 64 6f 6d 55 73 65 72 } //2 x_RandomUser
		$a_01_1 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 61 75 74 6f 63 6f 6e 6e 65 63 74 } //2 com.example.autoconnect
		$a_01_2 = {7c 21 7c 46 61 6c 73 65 7c 21 7c 46 61 6c 73 65 7c 21 7c 46 61 6c 73 65 7c 21 7c 46 61 6c 73 65 7c 21 7c 37 2e 30 2e 30 2e 31 30 7c 21 7c } //2 |!|False|!|False|!|False|!|False|!|7.0.0.10|!|
		$a_01_3 = {74 79 70 65 4f 66 53 4d 53 } //2 typeOfSMS
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}