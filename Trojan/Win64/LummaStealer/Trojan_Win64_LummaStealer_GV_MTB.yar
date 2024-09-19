
rule Trojan_Win64_LummaStealer_GV_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0c 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 4d 64 35 45 6e 63 6f 64 65 } //1 main.Md5Encode
		$a_01_1 = {6d 61 69 6e 2e 45 55 6b 63 4b 59 54 49 44 62 } //5 main.EUkcKYTIDb
		$a_01_2 = {6d 61 69 6e 2e 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 main.TerminateProcess
		$a_01_3 = {6d 61 69 6e 2e 6e 6c 5a 4d 7a 69 44 4d 71 76 } //5 main.nlZMziDMqv
		$a_01_4 = {6d 61 69 6e 2e 43 72 65 61 74 65 53 75 73 70 65 6e 64 65 64 50 72 6f 63 65 73 73 } //1 main.CreateSuspendedProcess
		$a_01_5 = {6d 61 69 6e 2e 52 65 73 75 6d 65 54 68 72 65 61 64 } //1 main.ResumeThread
		$a_01_6 = {6d 61 69 6e 2e 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 main.WriteProcessMemory
		$a_01_7 = {6d 61 69 6e 2e 57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 main.Wow64SetThreadContext
		$a_01_8 = {6d 61 69 6e 2e 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 main.GetThreadContext
		$a_01_9 = {4c 77 4e 4f 72 41 78 55 56 59 2f 6d 61 69 6e 2e 67 6f } //5 LwNOrAxUVY/main.go
		$a_01_10 = {6d 61 69 6e 2e 6e 77 50 58 41 4e 64 76 62 4c } //1 main.nwPXANdvbL
		$a_01_11 = {6d 61 69 6e 2e 71 57 77 76 66 65 4b 61 43 54 } //1 main.qWwvfeKaCT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*5+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=24
 
}