
rule TrojanDownloader_Win32_Agent_ABF{
	meta:
		description = "TrojanDownloader:Win32/Agent.ABF,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_00_0 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 51 53 56 8b f1 33 d2 c7 46 18 0f 00 00 00 89 56 14 57 89 74 24 0c 88 56 04 8b 7c 24 20 } //5
		$a_01_1 = {62 49 53 30 64 45 70 77 4d 32 75 69 64 33 43 6d 64 6f 4f 73 66 54 35 73 5a 58 4b 69 64 32 6d 72 62 54 } //5 bIS0dEpwM2uid3CmdoOsfT5sZXKid2mrbT
		$a_01_2 = {30 35 31 32 32 37 31 31 } //5 05122711
		$a_01_3 = {65 59 42 76 41 48 79 74 } //5 eYBvAHyt
		$a_01_4 = {25 73 5c 25 73 25 73 2e 25 73 } //5 %s\%s%s.%s
		$a_00_5 = {6e 65 77 71 71 5c 41 64 57 69 6e } //1 newqq\AdWin
		$a_01_6 = {43 3a 5c 75 70 2e 64 6c 6c 00 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=26
 
}