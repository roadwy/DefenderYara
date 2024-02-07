
rule Trojan_AndroidOS_FoncySms_B{
	meta:
		description = "Trojan:AndroidOS/FoncySms.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 6f 74 20 72 65 67 69 73 74 72 65 64 20 61 70 70 6c 69 63 61 74 69 6f 6e } //01 00  not registred application
		$a_01_1 = {41 6e 64 72 6f 69 64 42 6f 74 41 63 74 69 76 69 74 79 2e 6a 61 76 61 } //01 00  AndroidBotActivity.java
		$a_01_2 = {53 48 45 4c 4c 5f 69 6e } //01 00  SHELL_in
		$a_01_3 = {62 6f 74 2f 66 69 6c 65 73 2f 72 6f 6f 74 65 64 } //00 00  bot/files/rooted
	condition:
		any of ($a_*)
 
}