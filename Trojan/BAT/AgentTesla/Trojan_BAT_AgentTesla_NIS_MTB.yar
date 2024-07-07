
rule Trojan_BAT_AgentTesla_NIS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 66 00 66 00 67 00 67 00 66 00 66 00 66 00 66 00 66 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 2f } //1
		$a_81_1 = {73 73 73 73 73 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 73 73 73 73 73 73 66 61 73 61 64 73 73 73 73 73 73 73 } //1 sssssddddddddddddddddddddddddddssssssfasadsssssss
		$a_81_2 = {61 64 64 64 64 64 64 66 2e 65 78 65 } //1 addddddf.exe
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_6 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}