
rule Trojan_BAT_AgentTesla_BB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_00_0 = {01 57 1d b6 09 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 94 00 00 00 28 00 00 00 c3 } //3
		$a_81_1 = {69 73 50 61 73 73 77 6f 72 64 4d 61 73 6b 65 64 } //3 isPasswordMasked
		$a_81_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //3 SecurityProtocolType
		$a_81_3 = {64 69 73 63 6f 72 64 61 70 70 } //3 discordapp
		$a_81_4 = {41 70 61 72 74 6d 61 6e 4f 74 6f 2e 70 64 62 } //3 ApartmanOto.pdb
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}
rule Trojan_BAT_AgentTesla_BB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 73 65 72 76 65 72 53 74 61 72 74 65 64 } //1 _serverStarted
		$a_01_1 = {53 65 63 75 72 65 2e 4d 65 73 73 65 6e 67 65 72 2e 57 70 66 48 6f 73 74 } //1 Secure.Messenger.WpfHost
		$a_01_2 = {55 72 69 4b 69 6e 64 } //1 UriKind
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}