
rule VirTool_Win32_Antium_A_MTB{
	meta:
		description = "VirTool:Win32/Antium.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 6e 74 6e 69 75 6d 2f 70 6b 67 2f 63 6c 69 65 6e 74 2e } //1 antnium/pkg/client.
		$a_81_1 = {61 6e 74 6e 69 75 6d 2f 70 6b 67 2f 77 69 6e 67 6d 61 6e 2e 4d 61 6b 65 57 69 6e 67 6d 61 6e } //1 antnium/pkg/wingman.MakeWingman
		$a_81_2 = {55 70 73 74 72 65 61 6d 57 73 29 2e 43 6f 6e 6e 65 63 74 } //1 UpstreamWs).Connect
		$a_81_3 = {55 70 73 74 72 65 61 6d 4d 61 6e 61 67 65 72 29 2e 52 65 63 6f 6e 6e 65 63 74 57 65 62 73 6f 63 6b 65 74 } //1 UpstreamManager).ReconnectWebsocket
		$a_81_4 = {44 6f 77 6e 73 74 72 65 61 6d 4c 6f 63 61 6c 74 63 70 29 2e 4c 69 73 74 65 6e 41 64 64 72 } //1 DownstreamLocaltcp).ListenAddr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}