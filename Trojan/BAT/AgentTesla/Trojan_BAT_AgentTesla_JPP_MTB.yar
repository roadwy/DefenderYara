
rule Trojan_BAT_AgentTesla_JPP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 64 65 62 37 36 37 36 2d 65 61 33 35 2d 34 34 39 38 2d 61 63 32 36 2d 33 38 61 32 33 30 65 31 66 31 64 61 } //10 cdeb7676-ea35-4498-ac26-38a230e1f1da
		$a_03_1 = {00 07 09 06 09 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 6f ?? ?? ?? 0a 00 00 09 17 58 0d 09 06 6f ?? ?? ?? 0a 18 5b fe 04 13 04 11 04 } //1
		$a_81_2 = {43 6f 6e 73 6f 6c 65 50 6f 6b 65 72 47 61 6d 65 } //1 ConsolePokerGame
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*10+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=14
 
}