
rule Trojan_BAT_FormBook_NAH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f } //2 https://files.catbox.moe/
		$a_81_1 = {49 6e 6a 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c } //1 Injection successful
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_81_4 = {46 52 45 41 4b 59 2e 52 75 6e 50 45 } //1 FREAKY.RunPE
		$a_81_5 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //1 SecurityProtocolType
		$a_81_6 = {42 4c 41 53 54 } //1 BLAST
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}