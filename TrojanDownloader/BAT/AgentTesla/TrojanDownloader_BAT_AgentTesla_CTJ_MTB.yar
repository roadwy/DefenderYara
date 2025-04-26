
rule TrojanDownloader_BAT_AgentTesla_CTJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-1f] 2e 00 [0-05] 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5f 00 [0-20] 2e 00 6a 00 70 00 67 00 } //10
		$a_03_1 = {68 74 74 70 73 3a 2f 2f [0-1f] 2e [0-05] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f 77 69 74 68 6f 75 74 73 74 61 72 74 75 70 5f [0-20] 2e 6a 70 67 } //10
		$a_81_2 = {77 69 74 68 6f 75 74 73 74 61 72 74 75 70 2e 65 78 65 } //1 withoutstartup.exe
		$a_81_3 = {4d 61 6b 65 20 43 6f 6d 70 75 74 65 72 20 66 61 73 74 65 72 20 61 6e 64 20 6d 6f 72 65 20 73 65 63 75 72 65 } //1 Make Computer faster and more secure
		$a_81_4 = {4b 44 45 20 53 6f 66 74 77 61 72 65 73 } //1 KDE Softwares
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}