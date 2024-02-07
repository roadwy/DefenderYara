
rule Backdoor_Win32_Jabotma_A{
	meta:
		description = "Backdoor:Win32/Jabotma.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 76 62 73 5f 6a 61 6d 61 } //01 00  _vbs_jama
		$a_01_1 = {44 6f 45 78 65 63 32 } //01 00  DoExec2
		$a_01_2 = {2d 20 2d 2d 2d 20 73 65 6e 74 3a 20 2d 2d 2d 20 2d } //01 00  - --- sent: --- -
		$a_03_3 = {2f 62 6f 74 6e 65 74 7a 3f 61 3d 90 02 0a 26 67 75 69 64 3d 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}