
rule Trojan_BAT_AgentTesla_NR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 01 1a 62 11 01 1b 63 61 11 01 58 11 03 11 00 11 03 1f 0b 63 19 5f 94 58 61 59 13 08 20 13 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_NR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 02 26 16 72 ?? ?? ?? 70 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 } //5
		$a_01_1 = {44 00 6e 00 45 00 61 00 7a 00 } //1 DnEaz
		$a_01_2 = {44 6e 45 61 7a 2e 50 72 6f 70 65 72 74 69 65 73 } //1 DnEaz.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_NR_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {72 11 00 00 70 11 04 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 } //5
		$a_01_1 = {7a 00 75 00 6d 00 73 00 65 00 6c 00 } //1 zumsel
		$a_01_2 = {32 30 31 39 20 41 31 20 48 65 6c 70 44 65 73 6b } //1 2019 A1 HelpDesk
		$a_01_3 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_4 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
		$a_01_5 = {47 65 74 53 63 72 69 70 74 42 6c 6f 63 6b } //1 GetScriptBlock
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}
rule Trojan_BAT_AgentTesla_NR_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 54 69 63 54 61 63 54 6f 65 } //1 get_TicTacToe
		$a_81_1 = {54 69 63 54 61 63 54 6f 65 2e 54 69 63 54 61 63 54 6f 65 2e 72 65 73 6f 75 72 63 65 73 } //1 TicTacToe.TicTacToe.resources
		$a_81_2 = {54 69 63 54 61 63 54 6f 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 TicTacToe.My.Resources
		$a_81_3 = {54 69 63 54 61 63 54 6f 65 2e 66 72 6d 49 6e 74 72 6f 2e 72 65 73 6f 75 72 63 65 73 } //1 TicTacToe.frmIntro.resources
		$a_81_4 = {67 65 74 5f 48 6f 74 54 72 61 63 6b } //1 get_HotTrack
		$a_81_5 = {63 6d 64 48 61 72 64 5f 43 6c 69 63 6b } //1 cmdHard_Click
		$a_81_6 = {63 6d 64 47 65 74 31 41 6e 64 38 41 6e 64 31 36 5f 43 6c 69 63 6b } //1 cmdGet1And8And16_Click
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}