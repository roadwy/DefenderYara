
rule Ransom_Win64_Filecoder_PAY_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAY!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 69 6e 44 65 66 65 6e 64 22 20 2f 76 20 53 74 61 72 74 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 34 20 2f 66 } //2 reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 4 /f
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 76 20 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //2 reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
		$a_01_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 } //2 netsh advfirewall set allprofiles state off
		$a_01_3 = {68 74 74 70 3a 2f 2f 39 33 2e 31 38 34 2e 32 31 36 2e 33 34 3a 38 30 38 30 2f 6d 61 6c 77 61 72 65 2e 65 78 65 } //2 http://93.184.216.34:8080/malware.exe
		$a_01_4 = {25 73 2e 65 6e 63 72 79 70 74 65 64 } //1 %s.encrypted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}