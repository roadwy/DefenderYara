
rule Trojan_BAT_AgentTesla_NHE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 6e 11 08 6a 59 d4 11 04 1e 11 08 59 1e 5a 1f 3f 5f 64 20 90 01 03 00 6a 5f d2 9c 11 08 17 59 13 08 90 00 } //1
		$a_81_1 = {4d 6f 74 69 76 61 74 65 44 65 73 6b 74 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MotivateDesktop.Properties.Resources
		$a_01_2 = {59 75 41 6f 20 32 30 31 32 } //1 YuAo 2012
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_7 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_8 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //1 DownloadFileAsync
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}