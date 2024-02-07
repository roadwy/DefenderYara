
rule Backdoor_Win32_PcClient_gen_E{
	meta:
		description = "Backdoor:Win32/PcClient.gen!E,SIGNATURE_TYPE_PEHSTR,08 02 08 02 08 00 00 64 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 } //64 00  GET / HTTP/1.1
		$a_01_1 = {50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //64 00  POST /%s HTTP/1.1
		$a_01_2 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //64 00  \svchost.exe -k
		$a_01_3 = {53 65 72 76 69 63 65 4d 61 69 6e } //64 00  ServiceMain
		$a_01_4 = {57 69 6e 6c 6f 67 6f 6e } //0a 00  Winlogon
		$a_01_5 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //0a 00  SYSTEM\CurrentControlSet\Services\
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //0a 00  Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_01_7 = {5b 25 30 34 64 2d 25 30 32 64 2d 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d } //00 00  [%04d-%02d-%02d %02d:%02d:%02d]
	condition:
		any of ($a_*)
 
}