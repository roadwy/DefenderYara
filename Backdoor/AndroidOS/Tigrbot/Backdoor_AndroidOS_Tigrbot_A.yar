
rule Backdoor_AndroidOS_Tigrbot_A{
	meta:
		description = "Backdoor:AndroidOS/Tigrbot.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 53 75 63 63 65 73 73 3a } //1 sendSuccess:
		$a_01_1 = {72 6f 2e 74 65 6c 65 70 68 6f 6e 79 2e 64 69 73 61 62 6c 65 2d 63 61 6c 6c } //1 ro.telephony.disable-call
		$a_01_2 = {44 65 76 69 63 65 20 72 65 73 74 61 72 74 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 Device restart successfully.
		$a_01_3 = {76 6f 69 63 65 6d 61 69 6c 20 73 74 61 74 75 73 20 64 65 63 6f 64 69 6e 67 20 66 61 69 6c 65 64 } //1 voicemail status decoding failed
		$a_01_4 = {4e 65 77 20 53 49 4d 20 63 61 72 64 20 6e 75 6d 62 65 72 20 74 6f 20 73 65 6e 64 20 53 4d 53 20 6e 75 6d 62 65 72 20 69 73 20 6e 6f 77 2e } //1 New SIM card number to send SMS number is now.
		$a_01_5 = {72 65 74 72 79 20 63 6f 75 6e 74 20 69 73 20 74 6f 6f 20 6d 6f 72 65 2e 2e 2e } //1 retry count is too more...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}