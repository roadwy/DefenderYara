
rule TrojanDownloader_BAT_Ader_PAN_MTB{
	meta:
		description = "TrojanDownloader:BAT/Ader.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {31 38 38 2e 32 31 33 2e 31 36 37 2e 32 34 38 2f 64 6f 77 6e 6c 6f 61 64 2f 73 75 6f 6e 69 2f 47 41 41 74 74 65 73 61 2e 77 61 76 } //188.213.167.248/download/suoni/GAAttesa.wav  01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00 
		$a_80_2 = {48 69 64 65 53 74 61 72 74 42 61 72 } //HideStartBar  01 00 
		$a_80_3 = {4b 69 6c 6c 45 78 70 6c 6f 72 65 72 } //KillExplorer  01 00 
		$a_80_4 = {6d 63 69 53 65 6e 64 43 6f 6d 6d 61 6e 64 41 } //mciSendCommandA  00 00 
	condition:
		any of ($a_*)
 
}