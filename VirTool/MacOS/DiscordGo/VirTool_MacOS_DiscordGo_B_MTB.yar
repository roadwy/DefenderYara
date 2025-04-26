
rule VirTool_MacOS_DiscordGo_B_MTB{
	meta:
		description = "VirTool:MacOS/DiscordGo.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 69 73 63 6f 72 64 67 6f 2e 55 73 65 72 } //1 discordgo.User
		$a_01_1 = {64 69 73 63 6f 72 64 67 6f 2e 49 6e 74 65 6e 74 } //1 discordgo.Intent
		$a_01_2 = {55 73 65 72 41 76 61 74 61 72 44 65 63 6f 64 65 } //1 UserAvatarDecode
		$a_01_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 62 77 6d 61 72 72 69 6e 2f 64 69 73 63 6f 72 64 67 6f } //1 github.com/bwmarrin/discordgo
		$a_01_4 = {6f 73 2f 65 78 65 63 } //1 os/exec
		$a_01_5 = {44 69 73 63 6f 72 64 47 6f 2f 70 6b 67 2f 61 67 65 6e 74 } //1 DiscordGo/pkg/agent
		$a_01_6 = {67 69 74 68 75 62 2e 63 6f 6d 2f 67 6f 72 69 6c 6c 61 2f 77 65 62 73 6f 63 6b 65 74 } //1 github.com/gorilla/websocket
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}