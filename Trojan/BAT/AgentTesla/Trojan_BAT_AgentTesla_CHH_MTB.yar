
rule Trojan_BAT_AgentTesla_CHH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 90 01 01 07 91 09 61 d2 9c 07 17 58 0b 90 00 } //1
		$a_01_1 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //1 AssemblyResolve
		$a_01_2 = {00 44 65 63 72 79 70 74 00 } //1
		$a_01_3 = {00 43 6c 61 73 73 4c 69 62 72 61 72 79 00 } //1 䌀慬獳楌牢牡y
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_CHH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 08 20 00 01 00 00 6f 90 01 03 0a 08 17 6f 90 01 03 0a 08 72 90 01 03 70 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 1f 64 73 90 01 03 0a 1f 10 6f 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 17 73 90 01 03 0a 0b 07 02 16 02 8e 69 90 00 } //1
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}