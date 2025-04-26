
rule Trojan_Win32_Stealer_EN_MTB{
	meta:
		description = "Trojan:Win32/Stealer.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {fa 25 33 00 16 00 00 02 00 00 00 9b 00 00 00 72 00 00 00 7c 02 00 00 ca 04 00 00 7c 02 00 00 0a 00 00 00 90 01 00 00 bf } //3
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 } //1 encrypted_value
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_4 = {73 69 74 65 5f 75 72 6c } //1 site_url
		$a_01_5 = {66 65 64 65 72 61 74 69 6f 6e 5f 75 72 6c } //1 federation_url
		$a_01_6 = {66 6f 72 6d 53 75 62 6d 69 74 55 52 4c } //1 formSubmitURL
		$a_01_7 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //1 CryptUnprotectData
		$a_01_8 = {65 6d 62 65 64 64 65 72 5f 64 6f 77 6e 6c 6f 61 64 5f 64 61 74 61 } //1 embedder_download_data
		$a_01_9 = {74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //1 timePasswordChanged
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=12
 
}