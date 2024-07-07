
rule TrojanDownloader_BAT_AgentTesla_EPY_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4a 00 4f 00 4b 00 45 00 52 00 42 00 4c 00 41 00 44 00 45 00 45 00 2e 00 42 00 4c 00 41 00 5a 00 45 00 } //1 JOKERBLADEE.BLAZE
		$a_01_1 = {42 00 4c 00 41 00 5a 00 45 00 42 00 4c 00 41 00 5a 00 45 00 } //1 BLAZEBLAZE
		$a_01_2 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 } //1 transfer.sh
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_5 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_6 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}