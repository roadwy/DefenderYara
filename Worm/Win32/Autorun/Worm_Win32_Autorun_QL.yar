
rule Worm_Win32_Autorun_QL{
	meta:
		description = "Worm:Win32/Autorun.QL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 fa 5a 7f 41 8b 45 08 8a 4d fc 88 08 8b f4 8b 55 08 52 ff 15 90 01 04 3b f4 e8 90 01 04 83 f8 02 74 18 90 00 } //01 00 
		$a_01_1 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d } //01 00  shell\Auto\command=
		$a_01_2 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_3 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //00 00  shellexecute=
	condition:
		any of ($a_*)
 
}