
rule Backdoor_Win32_Qakbot_Y{
	meta:
		description = "Backdoor:Win32/Qakbot.Y,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 62 6f 74 5f 63 6f 6e 66 5f 70 61 74 68 3d 27 25 73 27 20 } //01 00  qbot_conf_path='%s' 
		$a_01_1 = {64 77 45 72 72 3d 25 75 20 71 62 6f 74 5f 72 75 6e 5f 6d 75 74 65 78 3d 27 25 73 27 20 75 73 65 72 6e 61 6d 65 3d 27 25 73 27 } //01 00  dwErr=%u qbot_run_mutex='%s' username='%s'
		$a_01_2 = {25 73 25 73 2f 64 75 70 69 6e 73 74 2e 70 68 70 3f 6e 3d 25 73 26 62 67 3d 25 73 26 72 3d 25 75 } //00 00  %s%s/dupinst.php?n=%s&bg=%s&r=%u
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}