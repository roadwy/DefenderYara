
rule TrojanSpy_AndroidOS_Secneo_A_xp{
	meta:
		description = "TrojanSpy:AndroidOS/Secneo.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 63 6f 6d 2e 73 65 63 6e 65 6f 2e 74 6d 70 } //01 00  /com.secneo.tmp
		$a_00_1 = {63 6f 6d 2f 73 65 63 73 68 65 6c 6c 2f 73 65 63 44 61 74 61 2f 46 69 6c 65 73 46 69 6c 65 4f 62 73 65 72 76 65 72 } //01 00  com/secshell/secData/FilesFileObserver
		$a_00_2 = {50 61 73 73 77 6f 72 64 4f 62 73 65 72 76 65 72 } //01 00  PasswordObserver
		$a_00_3 = {68 64 2e 66 69 73 68 2e 57 78 4d 6f 6e 69 74 6f 72 2e 57 78 4d 6f 6e 69 74 6f 72 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00  hd.fish.WxMonitor.WxMonitorApplication
		$a_00_4 = {5d 04 00 } //00 40 
	condition:
		any of ($a_*)
 
}