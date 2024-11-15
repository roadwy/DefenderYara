
rule HackTool_BAT_DiscordStealz_A_MTB{
	meta:
		description = "HackTool:BAT/DiscordStealz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 6d 6f 74 65 5f 61 64 6d 69 6e 5f 73 65 72 76 65 72 2e 66 72 6d 5f 64 69 73 63 6f 72 64 2e 72 65 73 6f 75 72 63 65 73 } //1 remote_admin_server.frm_discord.resources
		$a_01_1 = {66 69 6c 65 5f 6d 61 6e 61 67 65 72 } //1 file_manager
		$a_01_2 = {64 6f 6d 61 69 6e } //1 domain
		$a_01_3 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //1 System.Net.Sockets
		$a_01_4 = {66 69 6c 65 73 5f 63 6c 69 65 6e 74 5f 74 6f 5f 73 65 72 76 65 72 } //1 files_client_to_server
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}