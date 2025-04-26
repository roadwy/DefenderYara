
rule PWS_Win32_Fareit_AE_MTB{
	meta:
		description = "PWS:Win32/Fareit.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 6e fe 85 [0-15] 90 18 0f 6e da [0-15] 31 f2 [0-15] c3 } //1
		$a_03_1 = {0f 6e fe 83 [0-15] 90 18 0f 6e da [0-15] 31 f2 [0-15] c3 } //1
		$a_03_2 = {0f 6e fe 3d [0-15] 90 18 0f 6e da [0-15] 31 f2 [0-15] c3 } //1
		$a_03_3 = {0f 6e fe 81 [0-15] 90 18 0f 6e da [0-15] 31 f2 [0-15] c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}