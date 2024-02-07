
rule Trojan_BAT_AgentTesla_NMM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 73 64 66 6c 2e 64 6c 6c 23 } //01 00  #fsdfl.dll#
		$a_01_1 = {64 66 73 64 66 66 66 66 66 66 66 66 73 64 66 73 64 66 66 66 66 66 66 66 66 66 66 66 } //01 00  dfsdffffffffsdfsdfffffffffff
		$a_01_2 = {65 64 64 66 66 2e 64 6c 6c 23 } //01 00  eddff.dll#
		$a_01_3 = {66 64 66 73 64 64 2e 70 64 6c 6c 23 } //01 00  fdfsdd.pdll#
		$a_01_4 = {23 67 64 73 64 66 73 64 66 73 } //01 00  #gdsdfsdfs
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}