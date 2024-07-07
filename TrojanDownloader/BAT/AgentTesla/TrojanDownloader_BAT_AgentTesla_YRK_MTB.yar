
rule TrojanDownloader_BAT_AgentTesla_YRK_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.YRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 2f 00 73 00 47 00 64 00 41 00 62 00 31 00 2f 00 6e 00 65 00 77 00 31 00 2e 00 6a 00 70 00 65 00 67 00 } //1 transfer.sh/get/sGdAb1/new1.jpeg
		$a_01_1 = {6c 00 65 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //1 leta.exe
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_5 = {6e 69 67 67 65 72 } //1 nigger
		$a_01_6 = {6c 65 6d 70 61 64 6f } //1 lempado
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}