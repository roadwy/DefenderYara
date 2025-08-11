
rule Trojan_Win64_KillProc_GVA_MTB{
	meta:
		description = "Trojan:Win64/KillProc.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 61 76 6c 69 73 74 } //3 main.avlist
		$a_01_1 = {6d 61 69 6e 2e 69 73 50 72 6f 63 65 73 73 52 75 6e 6e 69 6e 67 } //1 main.isProcessRunning
		$a_01_2 = {6d 61 69 6e 2e 4c 6f 61 64 44 72 69 76 65 72 } //1 main.LoadDriver
		$a_01_3 = {6d 61 69 6e 2e 46 69 6e 64 50 72 6f 63 65 73 73 42 79 4e 61 6d 65 } //1 main.FindProcessByName
		$a_01_4 = {6d 61 69 6e 2e 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 42 79 49 4f 43 54 4c } //1 main.TerminateProcessByIOCTL
		$a_01_5 = {6d 61 69 6e 2e 52 65 67 69 73 74 65 72 50 72 6f 63 65 73 73 42 79 49 4f 43 54 4c } //1 main.RegisterProcessByIOCTL
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}