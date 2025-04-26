
rule VirTool_Win64_Godosesz_A_MTB{
	meta:
		description = "VirTool:Win64/Godosesz.A!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {64 6f 6d 61 69 6e } //1 domain
		$a_01_1 = {29 2e 48 6f 73 74 6e 61 6d 65 } //1 ).Hostname
		$a_01_2 = {2e 43 6f 6f 6b 69 65 73 } //1 .Cookies
		$a_01_3 = {53 65 74 53 65 73 73 69 6f 6e 54 69 63 6b 65 74 } //1 SetSessionTicket
		$a_01_4 = {2e 73 6f 63 6b 73 61 75 74 68 6d 65 74 68 6f 64 } //1 .socksauthmethod
		$a_01_5 = {75 73 65 72 61 67 65 6e 74 } //1 useragent
		$a_01_6 = {73 68 75 74 64 6f 77 6e } //1 shutdown
		$a_01_7 = {43 61 70 74 75 72 65 53 63 72 65 65 6e } //1 CaptureScreen
		$a_01_8 = {47 65 74 43 6c 69 70 62 6f 61 72 64 } //1 GetClipboard
		$a_01_9 = {6e 61 6d 65 64 70 69 70 65 } //1 namedpipe
		$a_01_10 = {6e 65 74 2f 68 74 74 70 2e 70 65 72 73 69 73 74 43 6f 6e 6e 57 72 69 74 65 72 2e 57 72 69 74 65 } //1 net/http.persistConnWriter.Write
		$a_01_11 = {43 68 61 6e 6e 65 6c 46 69 6c 65 53 65 6e 64 } //1 ChannelFileSend
		$a_01_12 = {61 64 64 43 6f 6e 6e } //1 addConn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}