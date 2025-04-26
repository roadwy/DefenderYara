
rule Trojan_BAT_AveMariaRAT_NYH_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 65 00 73 00 00 09 6f 00 75 00 72 00 63 00 00 05 65 00 73 } //1
		$a_01_1 = {4b 00 4b 00 4d 00 4b 00 4b 00 65 00 4b 00 4b 00 74 00 4b 00 4b 00 68 00 4b 00 4b 00 6f 00 4b 00 4b 00 64 00 4b 00 4b 00 30 00 4b 00 4b 00 } //1 KKMKKeKKtKKhKKoKKdKK0KK
		$a_01_2 = {41 00 52 00 41 00 42 00 45 00 } //1 ARABE
		$a_01_3 = {55 00 49 00 64 00 69 00 6a 00 73 00 69 00 64 00 37 00 } //1 UIdijsid7
		$a_01_4 = {47 00 65 00 74 00 4d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 4e 00 61 00 6d 00 65 00 73 00 } //1 GetManifestResourceNames
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}