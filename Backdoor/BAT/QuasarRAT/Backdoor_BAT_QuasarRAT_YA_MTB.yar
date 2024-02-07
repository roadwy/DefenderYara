
rule Backdoor_BAT_QuasarRAT_YA_MTB{
	meta:
		description = "Backdoor:BAT/QuasarRAT.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 51 75 61 73 61 72 52 41 54 2d 6d 61 73 74 65 72 5c } //01 00  \QuasarRAT-master\
		$a_01_1 = {78 43 6c 69 65 6e 74 2e 43 6f 72 65 2e 52 65 63 6f 76 65 72 79 2e 42 72 6f 77 73 65 72 73 } //01 00  xClient.Core.Recovery.Browsers
		$a_01_2 = {78 43 6c 69 65 6e 74 2e 43 6f 72 65 2e 52 65 63 6f 76 65 72 79 2e 46 74 70 43 6c 69 65 6e 74 73 } //01 00  xClient.Core.Recovery.FtpClients
		$a_01_3 = {47 65 74 53 61 76 65 64 50 61 73 73 77 6f 72 64 73 } //01 00  GetSavedPasswords
		$a_01_4 = {70 61 73 73 50 68 72 61 73 65 } //01 00  passPhrase
		$a_01_5 = {66 00 72 00 6d 00 42 00 6c 00 6f 00 63 00 6b 00 53 00 63 00 72 00 65 00 65 00 6e 00 } //00 00  frmBlockScreen
	condition:
		any of ($a_*)
 
}