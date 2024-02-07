
rule Backdoor_Win32_Drateam_B{
	meta:
		description = "Backdoor:Win32/Drateam.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 2f 44 52 41 54 2f } //01 00  ./DRAT/
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 7b 37 38 39 30 67 34 32 31 2d 62 31 67 66 2d 31 34 64 30 2d 38 39 62 62 2d 30 30 39 30 63 65 38 30 38 65 38 35 7d } //01 00  SOFTWARE\Microsoft\Active Setup\Installed Components\{7890g421-b1gf-14d0-89bb-0090ce808e85}
		$a_01_2 = {53 74 61 72 74 44 6c 6c } //01 00  StartDll
		$a_00_3 = {4d 53 2d 44 4f 53 20 43 61 72 72 79 20 6f 75 74 20 61 6e 64 20 46 61 69 6c 21 } //00 00  MS-DOS Carry out and Fail!
	condition:
		any of ($a_*)
 
}