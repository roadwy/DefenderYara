
rule Trojan_BAT_Keylogger_ADG_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {1f 0a 28 14 00 00 0a 00 16 13 06 2b 54 00 11 06 28 90 01 03 06 13 07 11 07 17 2e 0b 11 07 20 01 80 ff ff fe 90 00 } //03 00 
		$a_80_1 = {53 61 76 65 64 20 6b 65 79 73 20 66 72 6f 6d } //Saved keys from  03 00 
		$a_80_2 = {4b 65 79 73 74 72 6f 6b 65 73 20 73 61 76 65 64 20 66 72 6f 6d 20 75 73 65 72 } //Keystrokes saved from user  03 00 
		$a_80_3 = {53 6d 74 70 43 6c 69 65 6e 74 } //SmtpClient  03 00 
		$a_80_4 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  00 00 
	condition:
		any of ($a_*)
 
}