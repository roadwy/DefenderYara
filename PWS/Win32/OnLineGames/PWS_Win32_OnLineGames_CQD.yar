
rule PWS_Win32_OnLineGames_CQD{
	meta:
		description = "PWS:Win32/OnLineGames.CQD,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //0a 00  CreateToolhelp32Snapshot
		$a_01_1 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 61 } //03 00  urldownloadtofilea
		$a_01_2 = {00 77 6f 6f 6f 6c } //02 00  眀潯汯
		$a_01_3 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_01_4 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_01_5 = {61 76 70 63 63 2e 65 78 } //01 00  avpcc.ex
		$a_01_6 = {5f 61 76 70 6d 2e 65 78 } //01 00  _avpm.ex
		$a_01_7 = {61 76 70 33 32 2e 65 78 } //01 00  avp32.ex
		$a_01_8 = {6e 6f 72 74 6f 6e 2e 65 } //ec ff  norton.e
		$a_01_9 = {48 00 65 00 75 00 72 00 69 00 73 00 74 00 69 00 63 00 73 00 20 00 65 00 6e 00 67 00 69 00 6e 00 65 00 } //00 00  Heuristics engine
	condition:
		any of ($a_*)
 
}