
rule Trojan_BAT_AgentTesla_SA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8e 69 17 da 0b 16 0c 2b 32 06 02 02 7b 90 01 03 04 08 9a 28 90 01 03 06 28 90 01 03 0a 0a 08 02 7b 90 01 03 04 8e 69 17 da 2e 0c 06 72 90 01 03 70 28 90 01 03 0a 0a 08 17 d6 0c 08 07 31 ca 90 00 } //03 00 
		$a_80_1 = {4d 65 64 69 61 4d 61 6e 61 67 65 72 } //MediaManager  03 00 
		$a_80_2 = {43 73 76 44 61 74 61 62 61 73 65 } //CsvDatabase  03 00 
		$a_80_3 = {46 6f 72 6d 52 61 77 44 61 74 61 62 61 73 65 } //FormRawDatabase  03 00 
		$a_80_4 = {46 6f 72 6d 53 70 6c 61 73 68 53 63 72 65 65 6e } //FormSplashScreen  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_SA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 26 13 07 20 90 01 04 28 90 01 03 06 13 08 2b 39 11 07 11 08 9a 13 09 06 11 09 6f 90 01 03 06 25 26 2c 17 90 00 } //01 00 
		$a_80_1 = {5c 52 6f 61 6d 69 6e 67 5c 54 52 65 70 6c 61 63 65 6f 6b 52 65 70 6c 61 63 65 65 6e 52 65 70 6c 61 63 65 73 2e 74 52 65 70 6c 61 63 65 78 } //\Roaming\TReplaceokReplaceenReplaces.tReplacex  01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_80_3 = {25 61 70 70 64 61 74 61 25 5c 64 69 73 63 6f 72 64 5c } //%appdata%\discord\  01 00 
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}