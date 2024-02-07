
rule TrojanDownloader_Win32_Agent_OP{
	meta:
		description = "TrojanDownloader:Win32/Agent.OP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 4d 59 46 49 4c 45 53 25 5c 55 70 64 } //01 00  %MYFILES%\Upd
		$a_01_1 = {70 69 70 69 5f 64 61 65 } //01 00  pipi_dae
		$a_01_2 = {48 61 70 70 79 38 38 68 79 74 } //00 00  Happy88hyt
	condition:
		any of ($a_*)
 
}