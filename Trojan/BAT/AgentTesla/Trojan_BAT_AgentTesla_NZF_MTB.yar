
rule Trojan_BAT_AgentTesla_NZF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 03 20 00 87 93 03 6f 90 01 03 0a 80 90 01 04 38 90 00 } //1
		$a_81_1 = {31 38 35 2e 32 34 36 2e 32 32 30 2e 36 35 } //1 185.246.220.65
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NZF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 7e 90 01 01 00 00 04 07 91 61 d2 6f 90 01 01 00 00 0a 07 17 58 90 00 } //1
		$a_01_1 = {07 7e 01 00 00 04 8e 69 32 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NZF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {5f 95 02 3c 09 0a 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 26 00 00 00 07 00 00 00 08 00 00 00 08 00 00 00 11 00 00 00 15 00 00 00 28 00 00 00 06 00 00 00 02 00 00 00 05 } //5
		$a_01_1 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 NtWriteVirtualMemory
		$a_01_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}