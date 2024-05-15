
rule VirTool_Win64_Slekesz_A_MTB{
	meta:
		description = "VirTool:Win64/Slekesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 6b 65 79 6c 6f 67 } //01 00  .keylog
		$a_01_1 = {73 6c 61 63 6b 2e 55 70 6c 6f 61 64 } //01 00  slack.Upload
		$a_01_2 = {29 2e 52 65 6d 6f 74 65 41 64 64 72 } //01 00  ).RemoteAddr
		$a_01_3 = {53 6c 61 63 6b 6f 72 2f 70 6b 67 2f 63 6f 6d 6d 61 6e 64 2e 47 65 74 43 6f 6d 6d 61 6e 64 } //01 00  Slackor/pkg/command.GetCommand
		$a_01_4 = {53 6c 61 63 6b 6f 72 2f 61 67 65 6e 74 2e 67 6f } //01 00  Slackor/agent.go
		$a_01_5 = {2e 65 6e 63 72 79 70 74 } //01 00  .encrypt
		$a_01_6 = {6e 65 74 2f 68 74 74 70 2e 70 65 72 73 69 73 74 43 6f 6e 6e 57 72 69 74 65 72 2e 57 72 69 74 65 } //01 00  net/http.persistConnWriter.Write
		$a_01_7 = {2e 73 6f 63 6b 73 41 75 74 68 4d 65 74 68 6f 64 } //00 00  .socksAuthMethod
	condition:
		any of ($a_*)
 
}