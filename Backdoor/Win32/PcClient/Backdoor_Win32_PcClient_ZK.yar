
rule Backdoor_Win32_PcClient_ZK{
	meta:
		description = "Backdoor:Win32/PcClient.ZK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {78 c6 44 24 90 01 01 2e c6 44 24 90 01 01 61 c6 44 24 90 01 01 73 c6 44 24 90 01 01 70 c6 44 24 90 01 01 3f 90 00 } //03 00 
		$a_03_1 = {c6 45 e7 65 c6 45 e8 78 c6 45 e9 2e 90 02 08 c6 45 ea 61 c6 45 eb 73 90 02 08 c6 45 ec 70 90 00 } //02 00 
		$a_03_2 = {c6 45 e4 69 89 55 e5 c6 45 e5 6e 89 55 e9 90 02 08 c6 45 e7 65 89 55 90 01 01 c6 45 e8 78 90 02 04 c6 45 e9 2e 90 00 } //01 00 
		$a_00_3 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c } //01 00  PcClient.dll
		$a_00_4 = {32 30 30 00 25 73 25 73 25 73 } //01 00  〲0猥猥猥
		$a_00_5 = {53 65 72 76 69 63 65 4d 61 69 6e } //01 00  ServiceMain
		$a_00_6 = {46 75 63 6b 5f 44 72 77 65 62 } //00 00  Fuck_Drweb
	condition:
		any of ($a_*)
 
}