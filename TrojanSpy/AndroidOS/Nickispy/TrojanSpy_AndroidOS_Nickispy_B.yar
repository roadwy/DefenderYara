
rule TrojanSpy_AndroidOS_Nickispy_B{
	meta:
		description = "TrojanSpy:AndroidOS/Nickispy.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 72 6f 63 61 73 74 20 41 43 54 49 4f 4e 5f 42 4f 4f 54 5f 43 4f 4d 50 4c 45 54 45 44 20 72 65 63 65 69 76 65 72 } //1 Brocast ACTION_BOOT_COMPLETED receiver
		$a_01_1 = {68 61 73 20 62 65 65 6e 20 72 75 6e 6e 65 64 } //1 has been runned
		$a_01_2 = {70 68 6f 6e 65 73 70 79 2e 45 4e 44 5f 43 41 4c 4c } //1 phonespy.END_CALL
		$a_01_3 = {50 48 4f 4e 45 5f 53 50 59 5f 54 41 47 } //1 PHONE_SPY_TAG
		$a_01_4 = {42 72 6f 63 61 73 74 20 54 45 53 54 20 72 65 63 65 69 76 65 72 } //1 Brocast TEST receiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}