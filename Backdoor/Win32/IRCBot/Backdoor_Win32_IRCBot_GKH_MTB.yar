
rule Backdoor_Win32_IRCBot_GKH_MTB{
	meta:
		description = "Backdoor:Win32/IRCBot.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 53 74 3b 53 64 7d 90 01 01 42 89 53 74 31 c0 8b 43 74 c1 e0 02 8b 4b 6c 01 c1 8b 01 03 43 60 57 56 51 89 fe 89 c7 8b 4b 78 f3 a6 59 5e 5f 75 90 00 } //01 00 
		$a_01_1 = {63 2e 69 72 61 63 62 6c 61 72 6b 63 72 2e 64 65 74 } //01 00  c.iracblarkcr.det
		$a_01_2 = {61 64 66 74 53 6f 72 65 77 61 69 63 5c 4d 73 6f 72 6f 5c 57 66 74 64 6f 69 6e 5c 43 77 73 72 65 75 72 56 65 6e 74 69 6f 72 73 52 75 6e 5c } //00 00  adftSorewaic\Msoro\Wftdoin\CwsreurVentiorsRun\
	condition:
		any of ($a_*)
 
}