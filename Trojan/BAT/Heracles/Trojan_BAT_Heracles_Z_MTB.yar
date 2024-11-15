
rule Trojan_BAT_Heracles_Z_MTB{
	meta:
		description = "Trojan:BAT/Heracles.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 67 65 74 73 6f 6c 61 72 61 2e 64 65 76 } //1 https://getsolara.dev
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 67 69 73 74 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 66 75 72 72 79 6d 61 6e 31 32 } //1 https://gist.githubusercontent.com/furryman12
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_3 = {44 49 53 43 4f 52 44 } //1 DISCORD
		$a_81_4 = {55 70 6c 6f 61 64 44 61 74 61 } //1 UploadData
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}