
rule PWS_Win32_Fareit_Q_MTB{
	meta:
		description = "PWS:Win32/Fareit.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_03_1 = {31 34 24 33 90 0a ff 00 ff 37 [0-ff] 31 34 24 [0-ff] 8b 0c 24 [0-ff] 01 0c 18 [0-ff] 83 c4 04 } //1
		$a_03_2 = {31 34 24 3d 90 0a ff 00 ff 37 [0-ff] 31 34 24 [0-ff] 8b 0c 24 [0-ff] 01 0c 18 [0-ff] 83 c4 04 } //1
		$a_03_3 = {31 34 24 66 90 0a ff 00 ff 37 [0-ff] 31 34 24 [0-ff] 8b 0c 24 [0-ff] 85 c0 [0-ff] 01 0c 18 [0-ff] 83 c4 04 [0-ff] 83 c2 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}