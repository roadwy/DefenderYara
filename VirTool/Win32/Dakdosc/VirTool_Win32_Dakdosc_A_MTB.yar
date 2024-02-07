
rule VirTool_Win32_Dakdosc_A_MTB{
	meta:
		description = "VirTool:Win32/Dakdosc.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 61 61 43 32 2f 63 6d 64 2f 61 67 65 6e 74 } //01 00  DaaC2/cmd/agent
		$a_81_1 = {44 61 61 43 32 2f 70 6b 67 2f 63 32 61 67 65 6e 74 2f 65 78 65 63 77 69 6e 64 6f 77 73 } //01 00  DaaC2/pkg/c2agent/execwindows
		$a_81_2 = {62 77 6d 61 72 72 69 6e 2f 64 69 73 63 6f 72 64 67 6f } //01 00  bwmarrin/discordgo
		$a_81_3 = {64 69 73 63 6f 72 64 67 6f 2e 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //00 00  discordgo.EventHandler
	condition:
		any of ($a_*)
 
}