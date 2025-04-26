
rule VirTool_Win64_Ligelesz_A_MTB{
	meta:
		description = "VirTool:Win64/Ligelesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f 61 67 65 6e 74 } //1 ligolo-ng/cmd/agent
		$a_01_1 = {70 72 6f 74 6f 63 6f 6c 2e 4c 69 67 6f 6c 6f 44 65 63 6f 64 65 72 } //1 protocol.LigoloDecoder
		$a_01_2 = {29 2e 52 65 6d 6f 74 65 41 64 64 72 } //1 ).RemoteAddr
		$a_01_3 = {53 65 74 53 65 73 73 69 6f 6e 54 69 63 6b 65 74 } //1 SetSessionTicket
		$a_01_4 = {6d 61 78 50 61 79 6c 6f 61 64 53 69 7a 65 46 6f 72 57 72 69 74 65 } //1 maxPayloadSizeForWrite
		$a_01_5 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 72 65 6c 61 79 } //1 ligolo-ng/pkg/relay
		$a_01_6 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 61 67 65 6e 74 2e 48 61 6e 64 6c 65 43 6f 6e 6e } //1 ligolo-ng/pkg/agent.HandleConn
		$a_01_7 = {4c 69 73 74 65 6e 41 6e 64 53 65 72 76 65 } //1 ListenAndServe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}