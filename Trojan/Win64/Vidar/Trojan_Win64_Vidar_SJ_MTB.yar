
rule Trojan_Win64_Vidar_SJ_MTB{
	meta:
		description = "Trojan:Win64/Vidar.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {6d 61 69 6e 2e 54 65 72 6d } //1 main.Term
		$a_81_1 = {6d 61 69 6e 2e 4e 6f 64 65 49 44 } //1 main.NodeID
		$a_81_2 = {6d 61 69 6e 2e 4c 6f 67 45 6e 74 72 79 } //1 main.LogEntry
		$a_81_3 = {6d 61 69 6e 2e 4c 6f 67 49 6e 64 65 78 } //1 main.LogIndex
		$a_81_4 = {6d 61 69 6e 2e 42 69 74 73 74 72 65 61 6d } //1 main.Bitstream
		$a_81_5 = {6d 61 69 6e 2e 49 6d 6d 65 64 69 61 74 65 } //1 main.Immediate
		$a_81_6 = {6d 61 69 6e 2e 4d 6f 74 69 6f 6e 56 65 63 74 6f 72 } //1 main.MotionVector
		$a_81_7 = {6d 61 69 6e 2e 56 6f 74 65 52 65 71 75 65 73 74 } //1 main.VoteRequest
		$a_81_8 = {6d 61 69 6e 2e 56 6f 74 65 52 65 73 70 6f 6e 73 65 } //1 main.VoteResponse
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}