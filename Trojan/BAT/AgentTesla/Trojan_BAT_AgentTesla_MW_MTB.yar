
rule Trojan_BAT_AgentTesla_MW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 ff a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9b 00 00 00 72 00 00 00 79 02 00 00 c5 04 00 00 7c } //10
		$a_01_1 = {65 6d 62 65 64 64 65 72 5f 64 6f 77 6e 6c 6f 61 64 5f 64 61 74 61 } //1 embedder_download_data
		$a_01_2 = {74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 timePasswordChanged
		$a_01_3 = {43 6f 6f 6b 69 65 73 4e 6f 74 46 6f 75 6e 64 } //1 CookiesNotFound
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_6 = {73 65 74 5f 55 73 65 5a 69 70 36 34 57 68 65 6e 53 61 76 69 6e 67 } //1 set_UseZip64WhenSaving
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}