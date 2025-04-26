
rule Ransom_MSIL_ZiggyCrypter_PA_MTB{
	meta:
		description = "Ransom:MSIL/ZiggyCrypter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All your files have been encrypted
		$a_01_1 = {4d 00 69 00 6e 00 64 00 4c 00 61 00 74 00 65 00 64 00 2e 00 6a 00 70 00 67 00 } //1 MindLated.jpg
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 69 00 78 00 66 00 69 00 6c 00 65 00 73 00 2e 00 78 00 79 00 7a 00 2f 00 7a 00 69 00 67 00 67 00 79 00 2f 00 61 00 70 00 69 00 2f 00 69 00 6e 00 66 00 6f 00 2e 00 70 00 68 00 70 00 } //1 http://fixfiles.xyz/ziggy/api/info.php
		$a_01_3 = {5a 00 69 00 67 00 67 00 79 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 Ziggy Ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}