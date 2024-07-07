
rule Trojan_BAT_AgentTesla_NGM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 90 01 03 0a 20 90 01 03 00 da 13 05 11 05 28 90 01 03 0a 28 90 01 03 0a 13 06 07 11 06 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 6f 90 01 03 0a fe 04 13 07 11 07 2d b8 90 00 } //1
		$a_81_1 = {42 75 56 6e 56 69 66 56 75 5f 56 54 65 56 78 74 56 42 6f 56 78 } //1 BuVnVifVu_VTeVxtVBoVx
		$a_01_2 = {49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 } //1
		$a_01_3 = {df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 df 02 ef 02 df 02 df 02 df 02 df 02 df } //1
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}