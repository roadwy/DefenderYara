
rule Backdoor_BAT_Quasar_GG_MTB{
	meta:
		description = "Backdoor:BAT/Quasar.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {51 75 61 73 61 72 2e 43 6c 69 65 6e 74 2e } //Quasar.Client.  01 00 
		$a_80_1 = {50 61 79 6c 6f 61 64 } //Payload  01 00 
		$a_80_2 = {4d 6f 75 73 65 4b 65 79 48 6f 6f 6b } //MouseKeyHook  01 00 
		$a_80_3 = {6c 6f 67 69 6e } //login  01 00 
		$a_80_4 = {70 61 73 73 77 6f 72 64 } //password  01 00 
		$a_80_5 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //PK11SDR_Decrypt  01 00 
		$a_80_6 = {57 69 6e 53 43 50 44 65 63 72 79 70 74 } //WinSCPDecrypt  01 00 
		$a_80_7 = {45 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //EncryptedPassword  01 00 
		$a_80_8 = {53 68 75 74 64 6f 77 6e } //Shutdown  01 00 
		$a_80_9 = {52 65 76 65 72 73 65 50 72 6f 78 79 } //ReverseProxy  00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Quasar_GG_MTB_2{
	meta:
		description = "Backdoor:BAT/Quasar.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {51 75 61 73 61 72 43 6c 69 65 6e 74 } //QuasarClient  01 00 
		$a_80_1 = {70 61 79 6c 6f 61 64 } //payload  01 00 
		$a_80_2 = {78 43 6c 69 65 6e 74 2e 43 6f 72 65 } //xClient.Core  01 00 
		$a_80_3 = {42 6f 74 6b 69 6c 6c 65 72 } //Botkiller  01 00 
		$a_80_4 = {6b 65 79 6c 6f 67 67 65 72 } //keylogger  01 00 
		$a_80_5 = {69 6e 6a 65 63 74 6f 72 } //injector  01 00 
		$a_80_6 = {44 6f 57 65 62 63 61 6d 53 74 6f 70 } //DoWebcamStop  01 00 
		$a_80_7 = {44 6f 50 72 6f 63 65 73 73 4b 69 6c 6c } //DoProcessKill  01 00 
		$a_80_8 = {44 6f 43 6c 69 65 6e 74 55 70 64 61 74 65 } //DoClientUpdate  01 00 
		$a_80_9 = {44 6f 43 6c 69 65 6e 74 52 65 73 74 6f 72 65 44 65 6c } //DoClientRestoreDel  00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Quasar_GG_MTB_3{
	meta:
		description = "Backdoor:BAT/Quasar.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 6f 6f 6b 69 65 } //Cookie  01 00 
		$a_80_1 = {43 6f 6c 64 57 61 6c 6c 65 74 73 } //ColdWallets  01 00 
		$a_80_2 = {46 74 70 4d 61 6e 61 67 65 72 73 } //FtpManagers  01 00 
		$a_80_3 = {52 64 70 4d 61 6e 61 67 65 72 73 } //RdpManagers  01 00 
		$a_80_4 = {53 45 52 56 45 52 5f 43 52 45 44 45 4e 54 49 41 4c } //SERVER_CREDENTIAL  01 00 
		$a_80_5 = {42 72 6f 77 73 65 72 43 72 65 64 69 74 43 61 72 64 } //BrowserCreditCard  01 00 
		$a_80_6 = {50 61 79 6c 6f 61 64 } //Payload  01 00 
		$a_80_7 = {41 6e 74 69 56 4d } //AntiVM  01 00 
		$a_80_8 = {41 4e 54 49 56 49 52 55 53 } //ANTIVIRUS  01 00 
		$a_80_9 = {46 49 52 45 57 41 4c 4c } //FIREWALL  01 00 
		$a_80_10 = {41 4e 54 49 53 50 59 57 41 52 45 } //ANTISPYWARE  00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Quasar_GG_MTB_4{
	meta:
		description = "Backdoor:BAT/Quasar.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0b 00 00 0a 00 "
		
	strings :
		$a_80_0 = {51 75 61 73 61 72 43 6c 69 65 6e 74 } //QuasarClient  0a 00 
		$a_80_1 = {70 61 79 6c 6f 61 64 } //payload  01 00 
		$a_80_2 = {45 4e 41 42 4c 45 4c 4f 47 47 45 52 } //ENABLELOGGER  01 00 
		$a_80_3 = {48 49 44 45 4c 4f 47 44 49 52 45 43 54 4f 52 59 } //HIDELOGDIRECTORY  01 00 
		$a_80_4 = {44 6f 4d 6f 75 73 65 4d 6f 76 65 } //DoMouseMove  01 00 
		$a_80_5 = {44 6f 50 61 74 68 44 65 6c 65 74 65 } //DoPathDelete  01 00 
		$a_80_6 = {44 6f 50 61 74 68 52 65 6e 61 6d 65 } //DoPathRename  01 00 
		$a_80_7 = {44 6f 47 65 6e 65 72 61 74 65 53 65 65 64 } //DoGenerateSeed  01 00 
		$a_80_8 = {44 6f 43 6f 70 79 57 69 74 68 4e 65 77 50 61 73 73 77 6f 72 64 } //DoCopyWithNewPassword  01 00 
		$a_80_9 = {44 6f 53 68 65 6c 6c 45 78 65 63 75 74 65 } //DoShellExecute  01 00 
		$a_80_10 = {44 6f 50 61 72 73 65 53 65 63 72 65 74 4b 65 79 46 72 6f 6d 53 45 78 70 72 } //DoParseSecretKeyFromSExpr  00 00 
	condition:
		any of ($a_*)
 
}