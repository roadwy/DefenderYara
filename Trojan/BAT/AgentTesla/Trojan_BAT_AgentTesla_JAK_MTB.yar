
rule Trojan_BAT_AgentTesla_JAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {20 00 10 00 00 8d 90 01 03 01 0b 73 90 01 03 0a 0c 90 02 02 06 07 16 20 00 10 00 00 6f 90 01 03 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f 90 01 03 0a 90 02 03 09 16 fe 02 13 05 11 05 2d d0 08 6f 90 00 } //10
		$a_81_1 = {56 65 72 69 66 79 44 65 74 61 69 6c 73 } //1 VerifyDetails
		$a_81_2 = {44 42 5f 46 69 6e 64 65 72 } //1 DB_Finder
		$a_81_3 = {41 6e 61 6c 79 69 73 65 } //1 Analyise
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_JAK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.JAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {08 11 04 02 28 90 01 04 13 05 11 05 16 16 16 16 28 90 01 03 0a 28 90 01 03 0a 13 06 11 06 2c 33 00 06 06 6f 90 01 03 0a 19 8d 90 01 04 25 16 12 05 28 90 00 } //1
		$a_02_1 = {0a 0c 06 16 73 90 01 03 0a 0d 00 08 8d 90 01 03 01 13 04 09 11 04 16 08 6f 90 01 03 0a 26 11 04 13 05 de 16 90 00 } //1
		$a_02_2 = {09 11 05 02 11 05 91 08 61 06 11 04 91 61 d2 9c 11 04 03 6f 90 01 03 0a 17 59 fe 01 16 fe 01 13 06 11 06 2c 0a 90 00 } //1
		$a_81_3 = {52 65 73 6f 75 72 63 65 5f 4d 65 74 65 72 } //1 Resource_Meter
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}