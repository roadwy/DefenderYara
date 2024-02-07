
rule DDoS_BAT_Loioir_A{
	meta:
		description = "DDoS:BAT/Loioir.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 } //01 00 
		$a_01_1 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58 } //01 00 
		$a_01_2 = {69 00 72 00 63 00 42 00 6f 00 74 00 2e 00 41 00 70 00 70 00 5f 00 43 00 6f 00 6e 00 66 00 69 00 67 00 } //00 00  ircBot.App_Config
	condition:
		any of ($a_*)
 
}