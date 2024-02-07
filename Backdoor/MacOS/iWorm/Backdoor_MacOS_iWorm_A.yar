
rule Backdoor_MacOS_iWorm_A{
	meta:
		description = "Backdoor:MacOS/iWorm.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 0a 00 00 05 00 "
		
	strings :
		$a_00_0 = {2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 53 74 61 72 74 75 70 49 74 65 6d 73 2f 64 69 76 78 2f 53 74 61 72 74 75 70 50 61 72 61 6d 65 74 65 72 73 2e 70 6c 69 73 74 } //05 00  /System/Library/StartupItems/divx/StartupParameters.plist
		$a_00_1 = {63 68 6d 6f 64 20 37 35 35 20 2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 53 74 61 72 74 75 70 49 74 65 6d 73 2f 64 69 76 78 2f 64 69 76 78 } //01 00  chmod 755 /System/Library/StartupItems/divx/divx
		$a_00_2 = {44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 64 69 76 78 22 } //01 00  Description = "divx"
		$a_00_3 = {62 61 6e 61 64 64 } //01 00  banadd
		$a_00_4 = {70 32 70 6c 6f 63 6b } //01 00  p2plock
		$a_00_5 = {70 32 70 69 68 69 73 74 73 69 7a 65 } //01 00  p2pihistsize
		$a_00_6 = {70 32 70 70 65 65 72 70 6f 72 74 } //01 00  p2ppeerport
		$a_00_7 = {73 65 6e 64 6c 6f 67 73 } //01 00  sendlogs
		$a_00_8 = {75 70 74 69 6d 65 } //05 00  uptime
		$a_00_9 = {71 77 66 6f 6a 7a 6c 6b 2e 66 72 65 65 68 6f 73 74 69 61 2e 63 6f 6d } //00 00  qwfojzlk.freehostia.com
	condition:
		any of ($a_*)
 
}