
rule TrojanDownloader_BAT_AgentTesla_CTT_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 6b 65 64 61 69 6f 72 61 6e 67 6d 65 6c 61 79 75 2e 78 79 7a 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 77 69 74 68 6f 75 74 73 74 61 72 74 75 70 5f 4b 6b 78 6a 70 6a 6d 65 2e 62 6d 70 } //01 00  https://kedaiorangmelayu.xyz/loader/uploads/withoutstartup_Kkxjpjme.bmp
		$a_81_1 = {41 77 61 6b 65 53 65 72 76 65 72 } //01 00  AwakeServer
		$a_81_2 = {43 61 6c 6c 53 65 72 76 65 72 } //01 00  CallServer
		$a_81_3 = {49 6e 73 74 61 6e 74 69 61 74 65 53 65 72 76 65 72 } //01 00  InstantiateServer
		$a_81_4 = {77 69 74 68 6f 75 74 73 74 61 72 74 75 70 2e 65 78 65 } //00 00  withoutstartup.exe
	condition:
		any of ($a_*)
 
}