
rule HackTool_Win64_SplitPace_A_dha{
	meta:
		description = "HackTool:Win64/SplitPace.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,20 03 20 03 08 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 4e 65 77 53 65 73 73 69 6f 6e } //100 main.(*Client).NewSession
		$a_01_1 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 50 72 6f 63 65 73 73 69 6e 67 4d 65 73 73 61 67 65 73 } //100 main.(*Client).ProcessingMessages
		$a_01_2 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 4d 61 6b 65 4d 65 73 73 61 67 65 } //100 main.(*Client).MakeMessage
		$a_01_3 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 67 65 74 4d 65 73 73 61 67 65 73 46 72 6f 6d 53 65 72 76 65 72 } //100 main.(*Client).getMessagesFromServer
		$a_01_4 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 67 65 74 4f 6e 65 4d 65 73 73 61 67 65 46 72 6f 6d 53 65 72 76 65 72 } //100 main.(*Client).getOneMessageFromServer
		$a_01_5 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 44 69 73 63 6f 6e 6e 65 63 74 } //100 main.(*Client).Disconnect
		$a_01_6 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 41 75 74 68 } //100 main.(*Client).Auth
		$a_01_7 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 29 2e 52 61 6e 64 6f 6d 53 6c 65 65 70 } //100 main.(*Client).RandomSleep
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*100+(#a_01_6  & 1)*100+(#a_01_7  & 1)*100) >=800
 
}