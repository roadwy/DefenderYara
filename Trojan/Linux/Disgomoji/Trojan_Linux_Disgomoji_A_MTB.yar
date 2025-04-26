
rule Trojan_Linux_Disgomoji_A_MTB{
	meta:
		description = "Trojan:Linux/Disgomoji.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 41 6e 64 53 65 6e 64 54 6f 4f 73 68 69 } //1 uploadAndSendToOshi
		$a_01_1 = {6d 61 69 6e 2e 63 72 65 61 74 65 43 72 6f 6e 4a 6f 62 } //1 main.createCronJob
		$a_01_2 = {6d 61 69 6e 2e 7a 69 70 46 69 72 65 66 6f 78 50 72 6f 66 69 6c 65 } //1 main.zipFirefoxProfile
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 46 69 6c 65 46 72 6f 6d 55 52 4c } //1 downloadFileFromURL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}