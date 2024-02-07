
rule TrojanSpy_AndroidOS_Smbot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Smbot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 90 02 40 6d 61 6e 7a 2e 70 68 70 90 00 } //01 00 
		$a_00_1 = {63 6f 6e 74 65 6e 74 3a 2f 2f 73 6d 73 } //01 00  content://sms
		$a_00_2 = {44 4f 20 4e 4f 54 20 49 4e 54 45 52 52 55 50 54 } //01 00  DO NOT INTERRUPT
		$a_00_3 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 54 65 78 74 4d 65 73 73 61 67 65 28 22 90 02 13 22 } //00 00 
	condition:
		any of ($a_*)
 
}