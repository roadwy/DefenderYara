
rule TrojanSpy_Win32_Banker_USZ{
	meta:
		description = "TrojanSpy:Win32/Banker.USZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 36 35 58 53 36 50 52 43 62 71 6b 54 37 58 71 } //1 G65XS6PRCbqkT7Xq
		$a_01_1 = {47 70 66 53 47 4e 39 6e 54 4d 62 73 52 74 43 57 50 36 4b 57 53 37 39 6c 50 74 39 58 52 4d 35 70 4e 37 54 66 52 59 76 62 55 36 4b } //1 GpfSGN9nTMbsRtCWP6KWS79lPt9XRM5pN7TfRYvbU6K
		$a_01_2 = {47 70 66 53 48 36 7a 5a 54 4d 72 62 52 64 48 70 38 36 35 6b 50 32 31 4a 50 4e 48 71 51 4d 76 64 53 72 6e 31 52 36 6d 57 4c 4e 44 62 53 64 44 53 4a 4d 4c 6b 54 49 31 39 52 63 62 5a 51 4d 35 6f 4e 35 31 6f 52 73 54 6f 4f 4d 72 58 53 72 6e 39 52 63 62 5a 51 4d 35 69 51 4e 66 58 53 62 6e 74 51 4d 75 6b 50 4e 58 62 } //1 GpfSH6zZTMrbRdHp865kP21JPNHqQMvdSrn1R6mWLNDbSdDSJMLkTI19RcbZQM5oN51oRsToOMrXSrn9RcbZQM5iQNfXSbntQMukPNXb
		$a_01_3 = {47 70 66 53 48 36 7a 5a 54 4d 72 62 52 64 48 70 38 36 35 6b 50 32 31 4a 50 4e 48 71 51 4d 76 64 53 72 6e 31 52 36 6d 57 4c 4e 44 62 53 64 44 53 53 74 48 58 53 64 47 57 52 4d 4c 6b 54 4c 6e 6d 53 63 7a 64 53 63 35 6a 53 72 6e 70 54 36 35 6f 54 37 4c 6d 4e 37 54 66 52 59 76 62 55 36 4b } //1 GpfSH6zZTMrbRdHp865kP21JPNHqQMvdSrn1R6mWLNDbSdDSStHXSdGWRMLkTLnmSczdSc5jSrnpT65oT7LmN7TfRYvbU6K
		$a_01_4 = {4b 73 7a 63 54 37 54 58 53 63 4c 53 4a 4d 62 5a 53 63 7a 70 52 73 50 71 4e 35 54 66 52 63 48 6c 54 74 44 53 47 74 4c 6f 53 63 4c 6b 54 35 50 62 53 64 44 66 52 73 76 53 48 4e 58 6d 52 36 7a 6f 50 4e 38 } //1 KszcT7TXScLSJMbZSczpRsPqN5TfRcHlTtDSGtLoScLkT5PbSdDfRsvSHNXmR6zoPN8
		$a_01_5 = {4e 35 44 46 48 62 48 4e 47 4c 39 35 4e 34 72 66 4f 74 39 6c 53 73 7a 63 54 35 6e 4e 51 4d 76 61 52 74 54 70 38 34 76 4b 4e 34 44 72 53 64 39 62 52 64 48 4d 50 4e 39 70 51 4d 7a 6b } //1 N5DFHbHNGL95N4rfOt9lSszcT5nNQMvaRtTp84vKN4DrSd9bRdHMPN9pQMzk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}