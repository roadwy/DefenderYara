
rule TrojanDownloader_Win32_AgentRazy_SN_MTB{
	meta:
		description = "TrojanDownloader:Win32/AgentRazy.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6d 61 73 74 65 72 67 61 6d 65 6e 61 6d 65 70 65 72 2e 63 6c 75 62 } //01 00  mastergamenameper.club
		$a_00_1 = {62 72 6f 77 73 65 72 2e 65 78 65 } //01 00  browser.exe
		$a_00_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 72 00 } //01 00  SOFTWARE\Machiner
		$a_01_3 = {6b 00 5f 00 74 00 61 00 67 00 } //01 00  k_tag
		$a_01_4 = {33 00 5f 00 74 00 61 00 67 00 } //01 00  3_tag
		$a_00_5 = {2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 2f 00 6e 00 20 00 33 00 30 00 30 00 } //00 00  /C ping 127.0.0.1 /n 300
	condition:
		any of ($a_*)
 
}