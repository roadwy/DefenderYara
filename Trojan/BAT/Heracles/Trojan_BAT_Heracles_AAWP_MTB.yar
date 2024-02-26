
rule Trojan_BAT_Heracles_AAWP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 7e 01 00 00 04 6f 90 01 01 00 00 0a 06 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 02 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0c 08 07 16 73 90 01 01 00 00 0a 0d 09 73 90 01 01 00 00 0a 13 04 11 04 6f 90 01 01 00 00 0a 13 05 de 2a 11 04 2c 07 11 04 6f 90 01 01 00 00 0a dc 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_01_3 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 } //fb ff  C:\TEMP\
		$a_01_4 = {5c 49 57 42 5c 70 61 63 6b 61 67 69 6e 67 5c 54 70 6d 49 6e 69 74 69 61 6c 69 7a 65 72 5c 54 70 6d 45 4b 50 75 62 6c 69 63 4b 65 79 45 78 70 6f 72 74 65 72 5c 54 70 6d 45 4b 50 75 62 6c 69 63 4b 65 79 45 78 70 6f 72 74 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 54 70 6d 45 4b 50 75 62 6c 69 63 4b 65 79 45 78 70 6f 72 74 65 72 2e 70 64 62 } //00 00  \IWB\packaging\TpmInitializer\TpmEKPublicKeyExporter\TpmEKPublicKeyExporter\obj\Release\TpmEKPublicKeyExporter.pdb
	condition:
		any of ($a_*)
 
}