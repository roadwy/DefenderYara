
rule Ransom_Win64_Encoder_BMX_MTB{
	meta:
		description = "Ransom:Win64/Encoder.BMX!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 77 69 6e 64 6f 77 73 2e 7e 62 74 } //1 $windows.~bt
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //1 DisableRealtimeMonitoring
		$a_01_2 = {76 73 73 61 64 6d 69 6e } //1 vssadmin
		$a_01_3 = {73 68 61 64 6f 77 73 } //1 shadows
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_6 = {2e 62 6c 61 63 6b 6f 75 74 } //1 .blackout
		$a_01_7 = {47 6c 6f 62 61 6c 5c 42 6c 61 63 6b 6f 75 74 4d 75 74 65 78 } //1 Global\BlackoutMutex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}