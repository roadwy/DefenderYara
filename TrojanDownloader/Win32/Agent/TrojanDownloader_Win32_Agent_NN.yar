
rule TrojanDownloader_Win32_Agent_NN{
	meta:
		description = "TrojanDownloader:Win32/Agent.NN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 61 6f 68 61 6e 67 90 01 01 2e 65 78 65 00 90 00 } //01 00 
		$a_01_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 65 72 65 72 2e 6c 6e 6b 00 } //01 00 
		$a_01_2 = {45 78 70 6c 6f 72 65 72 5c 44 6f 6e 74 53 68 6f 77 4d 65 54 68 69 73 44 69 61 6c 6f 67 41 67 61 69 6e 00 } //01 00 
		$a_01_3 = {5c 57 69 6e 52 41 52 5c 57 69 6e 52 41 52 2e 6b 6e 6c 22 00 } //01 00  坜湩䅒屒楗剮剁欮汮"
		$a_03_4 = {69 65 78 70 6c 6f 72 65 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 70 70 90 02 04 2e 63 6f 6d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}