
rule TrojanDownloader_Win32_Agent_ZDF{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b cb 8b fa 8b d1 be dc b0 40 00 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 } //01 00 
		$a_00_1 = {62 68 6f 2e 64 6c 6c } //01 00  bho.dll
		$a_00_2 = {70 6c 61 79 2e 64 6c 6c } //01 00  play.dll
		$a_00_3 = {73 65 72 2e 65 78 65 } //01 00  ser.exe
		$a_00_4 = {6d 69 6e 69 75 70 2e 65 78 65 } //00 00  miniup.exe
	condition:
		any of ($a_*)
 
}