
rule Trojan_BAT_Keylogger_FGR_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.FGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {66 72 6d 73 70 6b 6c 67 72 5f 73 65 74 75 70 2e 72 65 73 6f 75 72 63 65 73 } //frmspklgr_setup.resources  03 00 
		$a_80_1 = {45 53 50 49 45 52 20 4b 45 59 4c 4f 47 47 45 52 } //ESPIER KEYLOGGER  03 00 
		$a_80_2 = {75 70 64 61 74 65 6b 65 79 } //updatekey  03 00 
		$a_80_3 = {73 70 6b 6c 67 72 2e 6c 6e 6b } //spklgr.lnk  03 00 
		$a_80_4 = {52 65 73 6f 75 72 63 65 73 2e 72 65 67 2e 64 65 73 2e 72 65 67 } //Resources.reg.des.reg  03 00 
		$a_80_5 = {73 70 6b 6c 67 72 2e 4c 69 63 65 6e 63 69 61 2e 74 78 74 } //spklgr.Licencia.txt  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Keylogger_FGR_MTB_2{
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