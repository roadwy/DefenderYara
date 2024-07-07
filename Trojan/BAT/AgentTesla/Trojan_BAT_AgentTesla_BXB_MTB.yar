
rule Trojan_BAT_AgentTesla_BXB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_02_0 = {0a 1f 64 73 90 01 03 0a 1f 10 6f 90 01 03 0a 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 17 73 90 01 03 0a 0b 07 02 16 02 8e 69 6f 90 01 03 0a 07 6f 90 01 03 0a de 0a 07 2c 06 07 6f 90 01 03 0a dc 06 6f 90 01 03 0a 0c de 0a 90 00 } //10
		$a_02_1 = {07 1f 64 73 90 01 03 0a 0c 73 90 01 03 0a 0d 09 20 00 01 00 00 6f 90 01 03 0a 09 17 6f 90 01 03 0a 03 2d 11 09 08 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 2b 0f 09 08 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 13 04 73 90 01 03 0a 13 05 90 00 } //10
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}