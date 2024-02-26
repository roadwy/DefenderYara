
rule Trojan_AndroidOS_Faketoken_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Faketoken.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 41 63 63 65 73 73 41 64 6d 69 6e } //01 00  callAccessAdmin
		$a_01_1 = {63 6f 6d 2f 73 79 73 74 65 6d 2f 66 } //01 00  com/system/f
		$a_01_2 = {63 75 73 74 6f 6d 2e 61 6c 61 72 6d 2e 69 6e 66 6f } //01 00  custom.alarm.info
		$a_01_3 = {45 58 54 52 41 5f 53 4b } //01 00  EXTRA_SK
		$a_01_4 = {41 44 44 5f 44 45 56 49 43 45 5f 41 44 4d 49 4e } //00 00  ADD_DEVICE_ADMIN
	condition:
		any of ($a_*)
 
}