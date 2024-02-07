
rule Trojan_BAT_Disco_DB_MTB{
	meta:
		description = "Trojan:BAT/Disco.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 48 4a 6c 62 57 6c 31 62 53 42 54 63 44 41 77 5a 6d 56 79 4b 67 3d 3d } //01 00  UHJlbWl1bSBTcDAwZmVyKg==
		$a_81_1 = {5f 45 6e 63 72 79 70 74 65 64 24 } //01 00  _Encrypted$
		$a_81_2 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 } //01 00  CryptoObfuscator
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}