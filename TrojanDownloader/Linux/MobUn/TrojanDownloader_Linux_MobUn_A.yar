
rule TrojanDownloader_Linux_MobUn_A{
	meta:
		description = "TrojanDownloader:Linux/MobUn.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6d 00 73 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  \Windows\msservice.exe
		$a_01_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 75 00 70 00 64 00 5f 00 6d 00 73 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  \Windows\upd_msservice.exe
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 6f 00 62 00 69 00 6c 00 65 00 75 00 6e 00 69 00 74 00 2e 00 72 00 75 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 67 00 65 00 74 00 73 00 74 00 72 00 3d 00 70 00 61 00 72 00 61 00 6d 00 } //01 00  http://mobileunit.ru/index.php?getstr=param
		$a_01_3 = {5c 53 72 76 55 70 64 61 74 65 72 2e 70 64 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}