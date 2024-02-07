
rule Trojan_Win32_Spynoon_PA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 50 00 55 00 42 00 4c 00 49 00 43 00 25 00 5c 00 70 00 75 00 74 00 74 00 79 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  %PUBLIC%\puttys.exe
		$a_01_1 = {33 00 32 00 36 00 38 00 39 00 36 00 35 00 37 00 2e 00 78 00 79 00 7a 00 } //01 00  32689657.xyz
		$a_01_2 = {57 69 6e 48 74 74 70 43 6f 6e 6e 65 63 74 } //01 00  WinHttpConnect
		$a_01_3 = {57 69 6e 48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 } //01 00  WinHttpOpenRequest
		$a_01_4 = {57 69 6e 48 74 74 70 52 65 63 65 69 76 65 52 65 73 70 6f 6e 73 65 } //01 00  WinHttpReceiveResponse
		$a_01_5 = {57 72 69 74 65 46 69 6c 65 } //00 00  WriteFile
	condition:
		any of ($a_*)
 
}