
rule VirTool_Win64_Myrddin_E_MTB{
	meta:
		description = "VirTool:Win64/Myrddin.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {29 2e 52 65 6d 6f 74 65 41 64 64 72 } //01 00  ).RemoteAddr
		$a_81_1 = {29 2e 48 6f 73 74 6e 61 6d 65 } //01 00  ).Hostname
		$a_81_2 = {29 2e 50 61 73 73 77 6f 72 64 } //01 00  ).Password
		$a_81_3 = {6e 65 74 2f 68 74 74 70 2e 70 65 72 73 69 73 74 43 6f 6e 6e 57 72 69 74 65 72 2e 57 72 69 74 65 } //01 00  net/http.persistConnWriter.Write
		$a_81_4 = {29 2e 47 65 74 53 65 73 73 69 6f 6e 54 69 63 6b 65 74 } //01 00  ).GetSessionTicket
		$a_81_5 = {29 2e 41 64 64 43 6f 6e 6e } //01 00  ).AddConn
		$a_81_6 = {29 2e 4e 65 77 53 65 73 73 69 6f 6e } //01 00  ).NewSession
		$a_81_7 = {29 2e 53 65 72 76 65 72 } //01 00  ).Server
		$a_81_8 = {29 2e 52 65 6d 6f 74 65 53 6f 63 6b } //01 00  ).RemoteSock
		$a_81_9 = {41 67 65 6e 74 49 6e 66 6f } //01 00  AgentInfo
		$a_81_10 = {67 69 74 68 75 62 2e 63 6f 6d 2f 4e 65 30 6e 64 30 67 } //00 00  github.com/Ne0nd0g
	condition:
		any of ($a_*)
 
}