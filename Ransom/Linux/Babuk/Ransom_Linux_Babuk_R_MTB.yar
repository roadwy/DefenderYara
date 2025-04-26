
rule Ransom_Linux_Babuk_R_MTB{
	meta:
		description = "Ransom:Linux/Babuk.R!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 61 64 57 65 61 74 68 65 72 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 BadWeather Ransomware
		$a_01_1 = {2e 62 61 64 77 65 61 74 68 65 72 } //1 .badweather
		$a_01_2 = {2e 62 77 5f 65 6e 63 72 79 70 74 69 6f 6e 6b 65 79 } //1 .bw_encryptionkey
		$a_01_3 = {42 61 64 57 65 61 74 68 65 72 20 45 53 58 49 20 45 6e 63 72 79 70 74 65 72 } //1 BadWeather ESXI Encrypter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}