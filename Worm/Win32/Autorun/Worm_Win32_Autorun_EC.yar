
rule Worm_Win32_Autorun_EC{
	meta:
		description = "Worm:Win32/Autorun.EC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 68 00 65 00 6c 00 6c 00 5c 00 53 00 63 00 61 00 6e 00 5f 00 57 00 69 00 74 00 68 00 5f 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 } //01 00  Shell\Scan_With_AntiVirus\command=
		$a_01_1 = {53 00 68 00 6f 00 77 00 53 00 75 00 70 00 65 00 72 00 48 00 69 00 64 00 64 00 65 00 6e 00 } //01 00  ShowSuperHidden
		$a_01_2 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  autorun.inf
		$a_01_3 = {47 00 52 00 49 00 53 00 4f 00 46 00 54 00 } //01 00  GRISOFT
		$a_01_4 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 21 00 } //01 00  AntiVirus detected!
		$a_01_5 = {6b 69 6c 6c 5f 70 72 6f 63 5f 73 68 65 6c 6c } //01 00  kill_proc_shell
		$a_01_6 = {4b 69 6c 6c 5f 50 72 6f 63 } //00 00  Kill_Proc
	condition:
		any of ($a_*)
 
}