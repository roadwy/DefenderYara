
rule Backdoor_Win32_Zegost_BY{
	meta:
		description = "Backdoor:Win32/Zegost.BY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 6c 6f 67 2e 64 61 74 } //01 00  \syslog.dat
		$a_01_1 = {54 61 62 00 43 6c 65 61 72 } //01 00 
		$a_00_2 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //01 00  winsta0\default
		$a_00_3 = {68 74 74 70 2f 31 2e 31 20 34 30 33 20 66 6f 72 62 69 64 64 65 6e } //01 00  http/1.1 403 forbidden
		$a_00_4 = {25 73 20 73 70 25 64 } //01 00  %s sp%d
		$a_03_5 = {ff 5c c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}