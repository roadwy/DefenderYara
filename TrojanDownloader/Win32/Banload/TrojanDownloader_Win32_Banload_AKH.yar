
rule TrojanDownloader_Win32_Banload_AKH{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKH,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbe 00 ffffffaa 00 07 00 00 "
		
	strings :
		$a_01_0 = {51 37 48 71 53 33 65 6c 42 74 } //100 Q7HqS3elBt
		$a_01_1 = {39 66 50 74 4c 66 52 36 58 62 53 63 72 62 42 64 44 66 54 36 4c 70 42 64 4c 6c 52 32 76 5a 52 73 71 6b 4f 64 38 6c } //50 9fPtLfR6XbScrbBdDfT6LpBdLlR2vZRsqkOd8l
		$a_01_2 = {39 6c 50 37 39 66 50 73 79 6b 53 73 35 69 52 73 72 58 52 6f 76 70 51 4e 48 62 53 6f 76 72 52 73 6d 6b } //50 9lP79fPsykSs5iRsrXRovpQNHbSovrRsmk
		$a_01_3 = {4f 70 66 53 4b 37 39 6c 50 74 39 58 52 4b 48 58 54 36 35 53 51 4e 48 73 53 6f 76 71 55 37 47 } //20 OpfSK79lPt9XRKHXT65SQNHsSovqU7G
		$a_01_4 = {53 73 35 6b 54 36 35 6b 50 36 4c 6f } //20 Ss5kT65kP6Lo
		$a_01_5 = {51 4e 48 58 54 47 } //20 QNHXTG
		$a_01_6 = {4d 72 50 31 4b 61 62 31 4c 61 4c 39 4b 71 7a 42 4e 47 } //20 MrP1Kab1LaL9KqzBNG
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20) >=170
 
}