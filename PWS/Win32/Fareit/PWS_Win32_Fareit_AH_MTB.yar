
rule PWS_Win32_Fareit_AH_MTB{
	meta:
		description = "PWS:Win32/Fareit.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 34 24 0f 90 0a ff 00 ff 37 [0-ff] 59 [0-ff] 89 0c 18 [0-ff] 83 (d2|c2) 04 [0-ff] 83 (|) c7 d7 04 } //1
		$a_03_1 = {31 34 24 f2 90 0a ff 00 ff 37 [0-ff] 59 [0-ff] 89 0c 18 [0-ff] 83 (d2|c2) 04 [0-ff] 83 (|) d7 c7 04 } //1
		$a_03_2 = {31 34 24 66 90 0a ff 00 ff 37 [0-ff] 59 [0-ff] 89 0c 18 [0-ff] 83 (d2|c2) 04 [0-ff] 83 (|) d7 c7 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}