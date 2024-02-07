
rule Trojan_BAT_AgentTesla_OZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0c 00 00 0b 00 "
		
	strings :
		$a_02_0 = {06 0a 06 28 90 02 04 28 90 02 04 0b 07 28 90 02 04 09 20 90 02 04 5a 20 90 02 04 61 38 90 02 04 09 20 90 02 04 5a 20 90 02 04 61 38 90 09 13 00 28 90 02 04 28 90 02 04 28 90 02 04 28 90 00 } //01 00 
		$a_81_1 = {50 54 4d 2e 4f 50 49 43 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PTM.OPIC.resources
		$a_81_2 = {4e 45 54 52 45 53 4f 55 52 43 45 } //01 00  NETRESOURCE
		$a_81_3 = {73 74 72 72 65 76 65 72 } //01 00  strrever
		$a_81_4 = {53 70 6c 61 73 68 46 6f 72 6d } //01 00  SplashForm
		$a_81_5 = {53 65 74 4c 6f 61 64 50 72 6f 67 72 65 73 73 } //01 00  SetLoadProgress
		$a_81_6 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_7 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  System.Security.Cryptography
		$a_81_8 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_81_9 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //01 00  ICryptoTransform
		$a_81_10 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //01 00  SymmetricAlgorithm
		$a_81_11 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}