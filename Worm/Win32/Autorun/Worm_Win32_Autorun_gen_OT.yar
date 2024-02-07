
rule Worm_Win32_Autorun_gen_OT{
	meta:
		description = "Worm:Win32/Autorun.gen!OT,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //01 00  [autorun]
		$a_01_1 = {6f 00 70 00 65 00 6e 00 3d 00 44 00 72 00 69 00 76 00 65 00 2e 00 64 00 72 00 76 00 2e 00 6c 00 6e 00 6b 00 00 00 } //01 00 
		$a_01_2 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 41 00 75 00 74 00 6f 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 44 00 72 00 69 00 76 00 65 00 2e 00 64 00 72 00 76 00 2e 00 6c 00 6e 00 6b 00 } //01 00  shell\Auto\command=Drive.drv.lnk
		$a_01_3 = {00 00 4e 00 6f 00 44 00 72 00 69 00 76 00 65 00 73 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}