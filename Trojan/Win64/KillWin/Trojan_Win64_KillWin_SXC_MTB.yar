
rule Trojan_Win64_KillWin_SXC_MTB{
	meta:
		description = "Trojan:Win64/KillWin.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 2a 20 3e 6e 75 6c 20 32 3e } //30 del /f /s /q C:\Windows\System32\* >nul 2>
		$a_01_1 = {53 70 61 6d 6d 69 6e 67 20 72 61 6e 73 6f 6d 20 6f 6e } //20 Spamming ransom on
		$a_01_2 = {5c 59 4f 55 52 5f 46 49 4c 45 53 5f 41 52 45 5f 45 4e 43 52 59 50 54 45 44 2e 74 78 74 } //10 \YOUR_FILES_ARE_ENCRYPTED.txt
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}