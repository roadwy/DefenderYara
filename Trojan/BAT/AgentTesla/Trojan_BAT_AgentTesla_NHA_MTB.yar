
rule Trojan_BAT_AgentTesla_NHA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 1f 00 00 04 72 90 01 02 00 70 73 90 01 02 00 0a 28 90 01 02 00 0a 72 90 01 02 00 70 28 90 01 02 00 0a 6f 90 01 02 00 0a 73 90 01 02 00 0a 25 6f 90 01 02 00 0a 90 00 } //5
		$a_01_1 = {4c 49 4e 43 41 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 LINCA.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NHA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 20 10 0f 00 00 28 90 01 03 06 5a 20 90 01 03 00 28 90 01 03 06 61 38 90 01 03 ff 02 20 90 01 03 00 28 90 01 03 06 2b 00 28 90 01 03 2b 6f 90 01 03 0a 90 00 } //5
		$a_01_1 = {54 52 46 53 47 42 56 43 58 46 44 } //1 TRFSGBVCXFD
		$a_01_2 = {4d 4a 43 4b 56 4b 4c 55 49 4f 52 } //1 MJCKVKLUIOR
		$a_01_3 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6c 61 73 73 } //1 ProcessInformationClass
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_NHA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 73 73 73 73 73 73 73 73 73 73 66 61 73 61 64 73 73 73 73 73 73 73 } //1 sssssssssssfasadsssssss
		$a_81_1 = {68 74 74 70 3a 2f 2f 67 66 66 67 67 66 66 66 66 66 72 6f 67 72 61 6d 73 2f } //1 http://gffggfffffrograms/
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}