
rule TrojanClicker_Win32_VB_CU{
	meta:
		description = "TrojanClicker:Win32/VB.CU,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 6a 00 2e 00 74 00 6f 00 6e 00 67 00 79 00 69 00 63 00 6a 00 2e 00 63 00 6f 00 6d 00 3a 00 38 00 37 00 32 00 2f 00 69 00 6e 00 73 00 65 00 72 00 74 00 2e 00 61 00 73 00 70 00 } //01 00  http://tj.tongyicj.com:872/insert.asp
		$a_01_1 = {62 00 61 00 63 00 6b 00 75 00 72 00 6c 00 3d 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 61 00 2e 00 6f 00 61 00 64 00 7a 00 2e 00 63 00 6f 00 6d 00 2f 00 6c 00 69 00 6e 00 6b 00 2f 00 43 00 2f 00 } //01 00  backurl=http://a.oadz.com/link/C/
		$a_01_2 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 76 00 68 00 6f 00 73 00 74 00 } //01 00  C:\WINDOWS\svhost
		$a_01_3 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  taskmgr.exe
		$a_01_4 = {64 65 6c 65 74 65 75 72 6c 63 61 63 68 65 65 6e 74 72 79 } //00 00  deleteurlcacheentry
	condition:
		any of ($a_*)
 
}