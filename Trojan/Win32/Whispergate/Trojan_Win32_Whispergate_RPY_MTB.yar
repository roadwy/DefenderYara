
rule Trojan_Win32_Whispergate_RPY_MTB{
	meta:
		description = "Trojan:Win32/Whispergate.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_3 = {31 34 34 2e 32 31 37 2e 39 30 2e 36 34 } //01 00  144.217.90.64
		$a_01_4 = {6f 70 65 6e 2e 65 78 65 } //01 00  open.exe
		$a_01_5 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 } //01 00  Start-Process
		$a_01_6 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //00 00  -WindowStyle Hidden
	condition:
		any of ($a_*)
 
}