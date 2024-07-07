
rule Ransom_Java_Filecoder_C_MTB{
	meta:
		description = "Ransom:Java/Filecoder.C!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 63 72 61 70 65 72 } //1 Scraper
		$a_00_1 = {50 65 77 43 72 79 70 74 } //1 PewCrypt
		$a_01_2 = {49 66 20 54 2d 53 65 72 69 65 73 20 62 65 61 74 73 20 50 65 77 64 69 65 70 69 65 20 54 48 45 20 50 52 49 56 41 54 45 20 4b 45 59 20 57 49 4c 4c 20 42 45 20 44 45 4c 45 54 45 44 20 41 4e 44 20 59 4f 55 20 46 49 4c 45 53 20 47 4f 4e 45 20 46 4f 52 45 56 45 52 } //1 If T-Series beats Pewdiepie THE PRIVATE KEY WILL BE DELETED AND YOU FILES GONE FOREVER
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}