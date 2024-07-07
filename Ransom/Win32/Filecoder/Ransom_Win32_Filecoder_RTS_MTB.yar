
rule Ransom_Win32_Filecoder_RTS_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.RTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {52 65 73 74 61 72 74 42 79 52 65 73 74 61 72 74 4d 61 6e 61 67 65 72 } //1 RestartByRestartManager
		$a_81_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All of your files have been encrypted
		$a_81_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 77 61 73 20 69 6e 66 65 63 74 65 64 20 20 77 69 74 68 20 61 20 72 61 6e 73 6f 6d 77 61 72 65 20 76 69 72 75 73 } //1 Your computer was infected  with a ransomware virus
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_4 = {42 69 74 63 6f 69 6e } //1 Bitcoin
		$a_81_5 = {43 6f 69 6e 6d 61 6d 61 } //1 Coinmama
		$a_81_6 = {42 69 74 70 61 6e 64 61 } //1 Bitpanda
		$a_81_7 = {48 6f 77 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 } //1 How to restore your file
		$a_81_8 = {43 6f 62 72 61 } //1 Cobra
		$a_81_9 = {43 6f 6e 74 61 63 74 73 20 45 6d 61 69 6c 3a } //1 Contacts Email:
		$a_81_10 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
		$a_81_11 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_12 = {74 62 69 72 64 63 6f 6e 66 69 67 } //1 tbirdconfig
		$a_81_13 = {73 71 62 63 6f 72 65 73 65 72 76 69 63 65 } //1 sqbcoreservice
		$a_81_14 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}