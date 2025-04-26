
rule PWS_Win32_Fareit_Y_MTB{
	meta:
		description = "PWS:Win32/Fareit.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 34 24 3d 90 0a 50 00 ff 37 [0-ff] 31 34 24 [0-ff] 59 [0-ff] (83 c2 04|83 d7 04) [0-ff] 51 [0-ff] 8f 04 18 } //1
		$a_03_1 = {31 34 24 85 90 0a 50 00 ff 37 [0-ff] 31 34 24 [0-ff] 59 [0-ff] (83 c2 04|83 d7 04) [0-ff] 51 [0-ff] 8f 04 18 } //1
		$a_03_2 = {31 34 24 eb 90 0a 50 00 ff 37 [0-ff] 31 34 24 [0-ff] 59 [0-ff] (83 c2 04|83 d7 04) [0-ff] 51 [0-ff] 8f 04 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}