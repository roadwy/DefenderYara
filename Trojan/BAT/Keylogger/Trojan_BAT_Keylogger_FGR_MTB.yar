
rule Trojan_BAT_Keylogger_FGR_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.FGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {02 16 7d 10 00 00 04 02 06 6a 28 2c 00 00 06 7d 10 00 00 04 02 7b 10 00 00 04 20 01 80 ff ff 33 26 02 } //05 00 
		$a_80_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  05 00 
		$a_80_2 = {67 65 74 5f 46 69 6c 65 53 79 73 74 65 6d } //get_FileSystem  04 00 
		$a_80_3 = {40 76 6f 72 66 69 6e 40 } //@vorfin@  04 00 
		$a_80_4 = {53 6d 74 70 43 6c 69 65 6e 74 } //SmtpClient  04 00 
		$a_80_5 = {4d 61 69 6c 4d 65 73 73 61 67 65 } //MailMessage  04 00 
		$a_80_6 = {73 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //set_Credentials  00 00 
	condition:
		any of ($a_*)
 
}