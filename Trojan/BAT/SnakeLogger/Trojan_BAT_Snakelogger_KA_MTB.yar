
rule Trojan_BAT_SnakeLogger_KA_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 } //1 downloadserver.duckdns.org
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {77 69 74 68 6f 75 74 73 74 61 72 74 75 70 2e 65 78 65 } //1 withoutstartup.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_SnakeLogger_KA_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeLogger.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 34 00 2e 00 35 00 34 00 2e 00 35 00 30 00 2e 00 33 00 31 00 2f 00 44 00 } //1 http://84.54.50.31/D
		$a_01_1 = {42 4e 42 55 4e 37 36 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BNBUN76.Properties.Resources.resources
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}