
rule Trojan_BAT_AgentTesla_LPI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 06 16 73 ?? ?? ?? 0a 13 08 00 } //1
		$a_03_1 = {03 8e 69 17 59 17 58 17 59 17 58 8d ?? ?? ?? 01 13 09 11 08 11 09 16 03 8e 69 6f ?? ?? ?? 0a 13 0a 11 09 11 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0c 00 de 0d } //1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_5 = {63 69 70 68 65 72 } //1 cipher
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}