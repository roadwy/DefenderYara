
rule PWS_Win32_Fareit_Q_MTB{
	meta:
		description = "PWS:Win32/Fareit.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_03_1 = {31 34 24 33 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8b 0c 24 90 02 ff 01 0c 18 90 02 ff 83 c4 04 90 00 } //01 00 
		$a_03_2 = {31 34 24 3d 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8b 0c 24 90 02 ff 01 0c 18 90 02 ff 83 c4 04 90 00 } //01 00 
		$a_03_3 = {31 34 24 66 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 8b 0c 24 90 02 ff 85 c0 90 02 ff 01 0c 18 90 02 ff 83 c4 04 90 02 ff 83 c2 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}