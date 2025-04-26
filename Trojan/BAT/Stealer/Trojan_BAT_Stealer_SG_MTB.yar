
rule Trojan_BAT_Stealer_SG_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c 00 } //1 FileZilla\recentservers.xml
		$a_01_1 = {77 00 77 00 77 00 2e 00 65 00 7a 00 69 00 72 00 69 00 7a 00 2e 00 63 00 6f 00 6d 00 } //1 www.eziriz.com
		$a_01_2 = {45 6d 62 65 64 64 65 64 53 51 4c 69 74 65 44 65 6d 6f 2e 70 64 62 } //1 EmbeddedSQLiteDemo.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}