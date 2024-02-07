
rule Trojan_BAT_AgentTesla_LHB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6a 6a 76 76 76 76 76 76 76 66 6c 68 68 68 68 68 68 68 68 68 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 73 73 73 73 73 76 68 6e } //0a 00  jjvvvvvvvflhhhhhhhhhfffffffffffffffsssssvhn
		$a_01_1 = {63 78 76 78 73 73 73 66 66 66 66 66 66 66 66 63 76 63 67 67 67 67 67 67 67 76 } //01 00  cxvxsssffffffffcvcgggggggv
		$a_01_2 = {66 64 73 2e 64 6c 6c 23 } //01 00  fds.dll#
		$a_01_3 = {23 67 67 67 67 67 } //01 00  #ggggg
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}