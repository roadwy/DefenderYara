
rule Worm_Win32_Autorun_ABO{
	meta:
		description = "Worm:Win32/Autorun.ABO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 04 37 80 38 e9 74 90 01 01 50 e8 90 01 04 85 c0 59 7d 90 01 01 33 c0 5f 5e 5b c9 c3 8b 48 01 8d 7c 01 05 33 c0 33 f6 03 f0 83 fe 06 90 00 } //01 00 
		$a_00_1 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_00_2 = {73 68 65 6c 6c 5c 45 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 25 53 } //01 00  shell\Explore\Command=%S
		$a_00_3 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 5f 00 4d 00 54 00 5f 00 } //01 00  PROCESS_MT_
		$a_00_4 = {73 00 76 00 72 00 77 00 73 00 63 00 2e 00 65 00 78 00 65 00 } //01 00  svrwsc.exe
		$a_00_5 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  autorun.inf
	condition:
		any of ($a_*)
 
}