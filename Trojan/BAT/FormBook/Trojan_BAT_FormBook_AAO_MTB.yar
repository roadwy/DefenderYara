
rule Trojan_BAT_FormBook_AAO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {0a 1d 2d 10 26 07 16 07 8e 69 17 2d 0a 26 26 26 07 0c de 21 0b 2b ee 28 } //01 00 
		$a_01_1 = {63 00 70 00 61 00 6e 00 65 00 6c 00 63 00 75 00 73 00 74 00 6f 00 6d 00 65 00 72 00 73 00 68 00 6f 00 73 00 74 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d 00 45 00 6e 00 76 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 6e 00 65 00 77 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2d 00 74 00 65 00 73 00 74 00 65 00 72 00 5f 00 44 00 79 00 67 00 6e 00 66 00 6c 00 61 00 66 00 2e 00 6a 00 70 00 67 00 } //01 00  cpanelcustomershost.duckdns.org/SystemEnv/uploads/newsoftware-tester_Dygnflaf.jpg
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}