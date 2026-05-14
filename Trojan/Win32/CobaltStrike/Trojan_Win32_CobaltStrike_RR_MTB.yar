
rule Trojan_Win32_CobaltStrike_RR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 30 31 2e 34 32 2e 31 37 35 2e 38 39 } //1 101.42.175.89
		$a_01_1 = {76 77 78 79 7a 31 32 33 34 35 36 37 38 39 30 31 31 31 31 31 31 31 31 } //1 vwxyz123456789011111111
		$a_01_2 = {68 6c 6c 6f 63 68 75 61 6c 41 68 56 69 72 74 54 } //1 hllochualAhVirtT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_CobaltStrike_RR_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 45 a0 50 e8 [0-04] 8b 95 [0-04] 34 56 8b 8d [0-04] 83 c4 04 88 04 11 42 89 95 90 1b 01 eb } //1
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 45 64 67 65 41 75 74 6f 4c 61 75 6e 63 68 5f 37 66 61 64 66 35 34 34 65 34 35 34 } //1 MicrosoftEdgeAutoLaunch_7fadf544e454
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}