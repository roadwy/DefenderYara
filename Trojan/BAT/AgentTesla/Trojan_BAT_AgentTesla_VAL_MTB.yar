
rule Trojan_BAT_AgentTesla_VAL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 33 31 65 36 33 34 30 63 2d 30 35 32 39 2d 34 63 33 33 2d 38 38 62 63 2d 38 65 37 39 66 64 61 33 31 37 33 33 } //01 00  $31e6340c-0529-4c33-88bc-8e79fda31733
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_2 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  DESCryptoServiceProvider
		$a_81_3 = {73 7a 48 53 6e 62 63 42 69 43 51 7a 72 68 48 7a 45 78 4b 76 6b 74 41 71 64 49 64 4c } //01 00  szHSnbcBiCQzrhHzExKvktAqdIdL
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_5 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //01 00  ContainsKey
		$a_81_6 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_7 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //01 00  https://
		$a_01_8 = {77 00 33 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //01 00  w3wp.exe
		$a_01_9 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //01 00  aspnet_wp.exe
		$a_01_10 = {44 00 6e 00 45 00 61 00 7a 00 2e 00 65 00 78 00 65 00 } //00 00  DnEaz.exe
	condition:
		any of ($a_*)
 
}