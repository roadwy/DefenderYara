
rule Trojan_BAT_Azorult_EC_MTB{
	meta:
		description = "Trojan:BAT/Azorult.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_2 = {50 61 74 63 68 43 6f 6d 70 6f 73 65 72 } //01 00  PatchComposer
		$a_01_3 = {63 72 52 63 65 6e 68 6e 67 63 6e 6e 6b 6e 39 64 76 } //01 00  crRcenhngcnnkn9dv
		$a_01_4 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 5f 00 5f 00 65 00 6d 00 70 00 74 00 79 00 } //01 00  C:\TEMP\__empty
		$a_01_5 = {52 00 63 00 65 00 6e 00 68 00 6e 00 67 00 63 00 6e 00 6e 00 6b 00 6e 00 79 00 64 00 76 00 7a 00 75 00 61 00 72 00 65 00 69 00 72 00 } //00 00  Rcenhngcnnknydvzuareir
	condition:
		any of ($a_*)
 
}