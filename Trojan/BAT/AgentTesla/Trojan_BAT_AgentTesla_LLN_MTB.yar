
rule Trojan_BAT_AgentTesla_LLN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 0b 00 00 1e 00 "
		
	strings :
		$a_01_0 = {64 73 61 64 66 66 66 77 74 77 66 66 66 66 66 66 66 67 73 73 73 73 73 64 66 2e 64 6c 6c 23 } //1e 00  dsadfffwtwfffffffgsssssdf.dll#
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //1e 00  FromBase64
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //0a 00  GetMethod
		$a_01_3 = {23 68 73 73 74 61 64 61 61 61 64 77 73 73 73 73 73 67 2e 64 6c 6c 23 } //0a 00  #hsstadaaadwsssssg.dll#
		$a_01_4 = {23 68 73 73 74 61 61 61 64 77 73 73 73 73 73 67 2e 64 6c 6c 23 } //01 00  #hsstaaadwsssssg.dll#
		$a_01_5 = {23 66 61 73 64 67 73 66 73 64 2e 64 6c 6c 23 } //01 00  #fasdgsfsd.dll#
		$a_01_6 = {23 61 66 61 2e 64 6c 6c 23 } //01 00  #afa.dll#
		$a_01_7 = {23 73 73 73 74 61 61 61 61 61 61 77 73 73 73 73 73 2e 64 6c 6c 23 } //01 00  #ssstaaaaaawsssss.dll#
		$a_01_8 = {23 66 66 66 64 73 61 73 77 74 66 2e 64 6c 6c 23 } //01 00  #fffdsaswtf.dll#
		$a_01_9 = {23 66 73 64 61 64 73 61 64 73 64 61 73 77 64 66 2e 64 6c 6c 23 } //01 00  #fsdadsadsdaswdf.dll#
		$a_01_10 = {23 61 64 73 61 64 64 64 64 64 64 64 61 64 61 64 61 61 77 73 2e 64 6c 6c 23 } //00 00  #adsadddddddadadaaws.dll#
	condition:
		any of ($a_*)
 
}