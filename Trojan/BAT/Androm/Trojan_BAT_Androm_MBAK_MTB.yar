
rule Trojan_BAT_Androm_MBAK_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {31 39 33 2e 35 36 2e 31 34 36 2e 31 31 34 } //1 193.56.146.114
		$a_81_1 = {66 61 64 73 67 68 73 65 72 66 67 61 65 7a 72 68 62 73 65 64 66 67 66 73 } //1 fadsghserfgaezrhbsedfgfs
		$a_81_2 = {78 7a 63 76 62 7a 78 66 72 67 68 7a 78 63 62 7a 64 66 67 73 61 79 7a 64 67 73 64 66 67 64 73 66 67 } //1 xzcvbzxfrghzxcbzdfgsayzdgsdfgdsfg
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_4 = {5a 69 70 43 6f 73 64 61 7a 2e 50 72 6f 70 65 72 74 69 65 } //1 ZipCosdaz.Propertie
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}