
rule Trojan_BAT_AgentTesla_NKJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 66 67 66 67 66 61 2e 64 6c 6c 23 } //01 00  #ffgfgfa.dll#
		$a_01_1 = {23 66 61 67 64 66 67 66 64 23 } //01 00  #fagdfgfd#
		$a_01_2 = {6b 67 64 66 67 64 66 66 23 } //01 00  kgdfgdff#
		$a_01_3 = {23 67 64 68 66 64 73 67 73 64 67 2e 64 6c 6c 23 } //01 00  #gdhfdsgsdg.dll#
		$a_01_4 = {23 73 61 64 61 61 61 61 67 66 64 67 61 64 61 61 61 64 76 63 78 76 61 64 61 61 64 66 67 64 73 2e 64 6c 6c 23 } //01 00  #sadaaaagfdgadaaadvcxvadaadfgds.dll#
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}