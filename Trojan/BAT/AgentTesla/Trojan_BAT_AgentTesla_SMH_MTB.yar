
rule Trojan_BAT_AgentTesla_SMH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 72 75 64 33 43 61 6d 61 64 61 73 4d 6f 74 61 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Crud3CamadasMota.Properties
		$a_81_1 = {43 72 75 64 33 43 61 6d 61 64 61 73 4d 6f 74 61 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Crud3CamadasMota.Form1.resources
		$a_81_2 = {43 6f 6e 63 61 74 } //1 Concat
		$a_81_3 = {46 61 69 6c 46 61 73 74 } //1 FailFast
		$a_81_4 = {43 72 75 64 33 43 61 6d 61 64 61 73 4d 6f 74 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Crud3CamadasMota.Properties.Resources.resources
		$a_81_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_SMH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SMH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 16 13 07 2b 64 00 07 11 06 11 07 6f c9 00 00 0a 13 08 08 12 08 28 ca 00 00 0a 6f cb 00 00 0a 00 08 6f cc 00 00 0a 20 00 b8 00 00 fe 04 13 09 11 09 2c 0e 08 12 08 28 cd 00 00 0a 6f cb 00 00 0a 00 08 6f cc 00 00 0a 20 00 b8 00 00 fe 04 13 0a 11 0a 2c 0e 08 12 08 28 ce 00 00 0a 6f cb 00 00 0a 00 00 11 07 17 58 13 07 11 07 07 6f a3 00 00 0a fe 04 13 0b 11 0b 2d 8c } //1
		$a_01_1 = {16 13 06 2b 68 16 13 07 2b 53 07 11 06 11 07 6f 6a 00 00 0a 13 08 08 12 08 28 6b 00 00 0a 6f 6c 00 00 0a 08 6f 6d 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 6e 00 00 0a 6f 6c 00 00 0a 08 6f 6d 00 00 0a 20 00 b8 00 00 2f 0d 08 12 08 28 6f 00 00 0a 6f 6c 00 00 0a 11 07 17 58 13 07 11 07 07 6f 70 00 00 0a 32 a3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}