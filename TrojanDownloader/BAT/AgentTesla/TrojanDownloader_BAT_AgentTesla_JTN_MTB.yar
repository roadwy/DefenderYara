
rule TrojanDownloader_BAT_AgentTesla_JTN_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.JTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {66 73 46 53 73 66 61 73 53 41 32 32 57 } //1 fsFSsfasSA22W
		$a_81_1 = {61 66 63 53 44 77 64 73 61 64 32 31 48 52 30 63 48 4d 36 } //1 afcSDwdsad21HR0cHM6
		$a_81_2 = {66 63 53 44 77 64 73 61 64 32 31 } //1 fcSDwdsad21
		$a_81_3 = {63 64 73 53 44 41 44 73 61 77 32 } //1 cdsSDADsaw2
		$a_81_4 = {73 64 67 61 66 61 64 67 67 34 74 67 53 } //1 sdgafadgg4tgS
		$a_81_5 = {6a 4a 41 53 48 4a 32 34 } //1 jJASHJ24
		$a_81_6 = {4d 6d 76 64 61 73 6b 6b 33 64 66 33 32 } //1 Mmvdaskk3df32
		$a_81_7 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=6
 
}