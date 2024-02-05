
rule TrojanDownloader_Win32_Agent_AAI{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAI,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 00 75 00 64 00 69 00 6f 00 43 00 44 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 49 00 63 00 6f 00 6e 00 } //02 00 
		$a_01_1 = {48 00 6f 00 73 00 74 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 33 00 32 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //02 00 
		$a_01_2 = {73 70 6f 6f 6c 63 76 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}