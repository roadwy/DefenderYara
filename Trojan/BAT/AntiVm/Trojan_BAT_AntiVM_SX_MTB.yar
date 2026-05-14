
rule Trojan_BAT_AntiVM_SX_MTB{
	meta:
		description = "Trojan:BAT/AntiVM.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 45 78 63 6c 75 73 69 6f 6e 73 5c 50 61 74 68 73 22 20 2f 76 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 } //reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" /v "C:\Windows\System32  20
		$a_80_1 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 69 63 72 6f 73 6f 66 74 45 64 67 65 5c 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72 22 20 2f 76 20 45 6e 61 62 6c 65 64 56 39 } //reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9  10
		$a_80_2 = {63 64 20 2f 64 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 50 6c 61 74 66 6f 72 6d 5c 34 2e 31 38 2a 20 26 26 20 4d 70 43 6d 64 52 75 6e 2e 65 78 65 20 2d 41 64 64 45 78 63 6c 75 73 69 6f 6e 20 2d 50 61 74 68 20 43 3a 5c 57 69 6e 64 6f 77 73 } //cd /d C:\ProgramData\Microsoft\Windows Defender\Platform\4.18* && MpCmdRun.exe -AddExclusion -Path C:\Windows  5
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5) >=35
 
}