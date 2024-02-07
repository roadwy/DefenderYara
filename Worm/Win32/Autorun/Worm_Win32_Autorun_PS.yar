
rule Worm_Win32_Autorun_PS{
	meta:
		description = "Worm:Win32/Autorun.PS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 ff d6 83 f8 02 74 4c fe c3 80 fb 5a 7e d7 } //01 00 
		$a_01_1 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d } //01 00  shell\Auto\command=
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //00 00  shellexecute=
	condition:
		any of ($a_*)
 
}