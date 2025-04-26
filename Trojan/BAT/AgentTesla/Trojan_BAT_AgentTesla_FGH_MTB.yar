
rule Trojan_BAT_AgentTesla_FGH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {48 4d 52 5f 44 42 44 61 74 61 53 65 74 } //1 HMR_DBDataSet
		$a_01_1 = {48 52 4d 5f 53 55 42 } //1 HRM_SUB
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {53 6f 63 6b 65 74 } //1 Socket
		$a_01_4 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //1 NetworkCredential
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_6 = {70 61 73 73 77 6f 72 64 5f 6b 65 79 64 6f 77 6e } //1 password_keydown
		$a_01_7 = {53 74 72 69 6e 67 52 65 61 64 65 72 } //1 StringReader
		$a_81_8 = {68 74 74 70 3a 2f 2f } //1 http://
		$a_01_9 = {48 52 4d 5f 53 55 42 5c 6f 62 6a 5c 44 65 62 75 67 5c 48 52 4d 5f 53 55 42 2e 70 64 62 } //1 HRM_SUB\obj\Debug\HRM_SUB.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_81_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}