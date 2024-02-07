
rule Trojan_Win32_Garvi_PAA_MTB{
	meta:
		description = "Trojan:Win32/Garvi.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 73 68 74 61 20 22 6a 61 76 61 73 63 72 69 70 74 3a 66 75 6e 63 74 69 6f 6e 20 67 65 74 54 28 61 29 7b 76 61 72 20 62 2c 63 3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 27 29 3b 72 65 74 75 72 6e 20 63 2e 4f 70 65 6e 28 27 47 45 54 27 2c 61 2c 21 31 29 2c 63 2e 53 65 6e 64 28 29 2c 62 3d 63 2e 52 65 73 70 6f 6e 73 65 54 65 78 74 2c 62 7d } //01 00  mshta "javascript:function getT(a){var b,c=new ActiveXObject('WinHttp.WinHttpRequest.5.1');return c.Open('GET',a,!1),c.Send(),b=c.ResponseText,b}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_03_2 = {6d 61 72 69 75 73 2f 6c 6f 61 64 65 72 2f 6c 2e 70 68 70 3f 90 02 0a 27 29 29 3b 22 90 00 } //01 00 
		$a_01_3 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //01 00  RegSetValueExA
		$a_01_4 = {52 65 67 43 72 65 61 74 65 4b 65 79 41 } //01 00  RegCreateKeyA
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_6 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00  GetCurrentProcess
		$a_01_7 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //00 00  TerminateProcess
	condition:
		any of ($a_*)
 
}