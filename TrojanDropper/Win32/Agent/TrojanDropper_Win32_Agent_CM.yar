
rule TrojanDropper_Win32_Agent_CM{
	meta:
		description = "TrojanDropper:Win32/Agent.CM,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 05 00 00 14 00 "
		
	strings :
		$a_01_0 = {eb 10 66 62 3a 43 2b 2b 48 4f 4f 4b 90 e9 } //0a 00 
		$a_00_1 = {5c 53 79 73 74 65 6d 5c 53 79 73 74 65 6d 33 32 2e 65 78 65 } //0a 00  \System\System32.exe
		$a_00_2 = {5c 53 79 73 74 65 6d 5c 75 70 64 61 74 65 2e 65 78 65 } //0a 00  \System\update.exe
		$a_00_3 = {5c 65 4d 75 6c 65 5c 49 6e 63 6f 6d 69 6e 67 5c } //01 00  \eMule\Incoming\
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}