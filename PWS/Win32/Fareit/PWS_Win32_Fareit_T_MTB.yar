
rule PWS_Win32_Fareit_T_MTB{
	meta:
		description = "PWS:Win32/Fareit.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_03_1 = {31 34 24 66 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 90 03 01 01 8b 89 0c 10 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //1
		$a_03_2 = {31 34 24 e9 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 90 03 01 01 8b 89 0c 10 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //1
		$a_03_3 = {31 34 24 85 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 90 03 01 01 8b 89 0c 10 90 02 ff 83 c2 04 90 02 ff 83 c7 04 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}