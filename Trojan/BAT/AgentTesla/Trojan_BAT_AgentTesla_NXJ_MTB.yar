
rule Trojan_BAT_AgentTesla_NXJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 39 61 33 36 36 64 38 36 2d 32 36 30 64 2d 34 65 65 64 2d 39 33 37 33 2d 34 64 39 36 35 61 36 36 37 64 36 65 } //1 $9a366d86-260d-4eed-9373-4d965a667d6e
		$a_01_1 = {47 6f 6f 64 56 73 45 76 69 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //1 GoodVsEvil.Properties.Resource
		$a_01_2 = {15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 2b 00 00 00 08 00 00 00 1c 00 00 00 43 } //1
		$a_01_3 = {62 00 cc 06 59 00 46 06 86 06 } //1
		$a_01_4 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}