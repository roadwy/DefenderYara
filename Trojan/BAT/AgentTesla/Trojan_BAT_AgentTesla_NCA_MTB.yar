
rule Trojan_BAT_AgentTesla_NCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 07 94 d1 0c 12 02 28 90 01 03 0a 28 90 01 03 0a 0a 07 17 58 0b 07 02 8e 69 32 90 00 } //01 00 
		$a_03_1 = {06 07 02 07 28 90 01 03 06 07 20 90 01 03 00 5d d1 61 d1 9d 07 17 58 0b 07 02 6f 90 01 03 0a 32 90 00 } //01 00 
		$a_01_2 = {04 03 1f 10 5d 91 61 2a } //01 00 
		$a_01_3 = {2c 00 2e 00 2d 00 65 00 78 00 2c 00 2e 00 2d 00 65 00 2e 00 73 00 72 00 2c 00 2e 00 2d 00 65 00 73 00 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NCA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 6d 64 61 61 61 61 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 61 61 61 61 61 2e 65 78 65 } //01 00  cmdaaaasssssssssssssssssssssssssssssssssssssssssssssssssaaaaa.exe
		$a_81_1 = {68 74 74 70 3a 2f 2f 75 73 65 72 3a 70 61 73 73 77 6f 72 64 40 77 77 77 2e 69 6e 63 6c 75 64 65 68 65 6c 70 2e 63 6f 6d 3a 38 30 38 32 2f 41 72 74 69 63 6c 65 2f 43 50 72 6f 67 72 61 6d 73 2f } //01 00  http://user:password@www.includehelp.com:8082/Article/CPrograms/
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_5 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  DESCryptoServiceProvider
	condition:
		any of ($a_*)
 
}