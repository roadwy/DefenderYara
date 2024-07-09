
rule PWS_Win32_Fareit_AJ_MTB{
	meta:
		description = "PWS:Win32/Fareit.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {38 62 3c 0a 75 [0-ff] 81 f7 [0-ff] 31 3c 08 [0-ff] 49 [0-40] 49 [0-40] 49 [0-40] 49 } //1
		$a_03_1 = {38 62 3c 0a eb [0-ff] 81 f7 [0-ff] 31 3c 08 [0-ff] 49 [0-40] 49 [0-40] 49 [0-40] 49 } //1
		$a_03_2 = {38 62 3c 0a 71 [0-ff] 81 f7 [0-ff] 31 3c 08 [0-ff] 49 [0-40] 49 [0-40] 49 [0-40] 49 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}