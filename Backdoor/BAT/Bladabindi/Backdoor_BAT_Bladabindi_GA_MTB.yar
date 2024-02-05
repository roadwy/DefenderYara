
rule Backdoor_BAT_Bladabindi_GA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {76 69 63 74 69 6d 4e 61 6d 65 } //victimName  01 00 
		$a_80_1 = {6b 65 79 6c 6f 67 67 65 72 } //keylogger  01 00 
		$a_80_2 = {69 73 43 6f 6e 6e 65 63 74 65 64 } //isConnected  01 00 
		$a_80_3 = {4d 6f 6e 69 74 6f 72 } //Monitor  01 00 
		$a_80_4 = {54 63 70 43 6c 69 65 6e 74 } //TcpClient  01 00 
		$a_80_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  01 00 
		$a_80_6 = {50 6c 75 67 69 6e } //Plugin  01 00 
		$a_80_7 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e } //CopyFromScreen  01 00 
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 6c } //Uninstall  00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Bladabindi_GA_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 07 16 73 90 01 03 0a 0c 1a 8d 90 01 03 01 0d 07 07 6f 90 01 03 0a 1b 6a da 6f 90 01 03 0a 00 07 09 16 1a 6f 90 01 03 0a 26 09 16 28 90 01 03 0a 13 04 07 16 6a 6f 90 01 03 0a 00 11 04 17 da 17 d6 17 da 17 d6 17 da 17 d6 8d 90 01 03 01 13 05 08 11 05 16 11 04 6f 90 01 03 0a 26 08 6f 90 01 03 0a 00 07 6f 90 01 03 0a 00 11 05 0a 2b 00 06 2a 90 00 } //01 00 
		$a_80_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  01 00 
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  00 00 
	condition:
		any of ($a_*)
 
}