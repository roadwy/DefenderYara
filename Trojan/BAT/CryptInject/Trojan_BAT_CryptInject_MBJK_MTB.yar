
rule Trojan_BAT_CryptInject_MBJK_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 64 00 69 00 67 00 6f 00 00 01 00 4d 42 00 69 } //01 00 
		$a_01_1 = {24 64 65 30 35 38 37 32 61 2d 62 38 38 61 2d 34 39 39 63 2d 62 36 61 61 2d 65 32 31 35 35 37 37 65 35 36 34 36 } //01 00  $de05872a-b88a-499c-b6aa-e215577e5646
		$a_01_2 = {42 69 74 47 75 61 72 64 2e 43 6f 6d 70 72 65 73 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  BitGuard.Compress.Properties.Resources.resource
		$a_01_3 = {41 65 73 4d 61 6e 61 67 65 64 } //01 00  AesManaged
		$a_01_4 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_01_5 = {53 74 72 69 6e 67 53 6f 72 74 65 72 } //00 00  StringSorter
	condition:
		any of ($a_*)
 
}