
rule Worm_Win32_Wahrecks_A{
	meta:
		description = "Worm:Win32/Wahrecks.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 f8 03 74 0c 66 83 f8 04 74 06 66 83 f8 02 75 5c } //01 00 
		$a_01_1 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 2f 52 45 43 59 43 4c 45 52 2e 7b 36 34 35 46 46 30 34 30 2d 35 30 38 31 2d 31 30 31 42 2d 39 46 30 38 2d 30 30 41 41 30 30 32 46 39 35 34 45 7d } //01 00  shell\open\Command=/RECYCLER.{645FF040-5081-101B-9F08-00AA002F954E}
		$a_01_2 = {57 53 57 48 41 43 4b 45 52 00 } //00 00  南䡗䍁䕋R
	condition:
		any of ($a_*)
 
}