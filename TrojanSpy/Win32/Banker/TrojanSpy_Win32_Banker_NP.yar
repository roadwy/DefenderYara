
rule TrojanSpy_Win32_Banker_NP{
	meta:
		description = "TrojanSpy:Win32/Banker.NP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 00 00 00 43 6f 6d 65 e7 6f 20 53 50 41 4d 20 42 74 6e 20 55 73 65 72 00 00 00 00 ff ff ff ff 0b 00 00 00 5c 77 6c 6f 67 73 32 2e 74 78 74 00 ff ff ff ff 17 00 00 00 49 6d 70 6f 73 73 69 76 65 6c 20 64 65 20 43 6f 6e 65 63 74 61 72 20 00 ff ff ff ff 10 00 00 00 46 61 6c 68 61 20 6e 61 20 63 6f 6e 65 78 61 6f 00 00 00 00 ff ff ff ff 19 00 00 00 43 6f 6e 65 63 74 61 64 6f 20 61 6f 20 73 65 72 76 69 64 6f 72 72 72 72 72 00 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 41 42 5c 57 41 42 34 5c 57 61 62 20 46 69 6c 65 20 4e 61 6d 65 } //01 00  Software\Microsoft\WAB\WAB4\Wab File Name
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 5c 30 30 30 30 30 30 30 31 } //00 00  Software\Microsoft\Internet Account Manager\Accounts\00000001
	condition:
		any of ($a_*)
 
}