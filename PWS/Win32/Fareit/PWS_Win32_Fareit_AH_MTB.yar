
rule PWS_Win32_Fareit_AH_MTB{
	meta:
		description = "PWS:Win32/Fareit.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 34 24 0f 90 0a ff 00 ff 37 90 02 ff 59 90 02 ff 89 0c 18 90 02 ff 83 90 03 01 01 d2 c2 04 90 02 ff 83 90 03 01 01 c7 d7 04 90 00 } //01 00 
		$a_03_1 = {31 34 24 f2 90 0a ff 00 ff 37 90 02 ff 59 90 02 ff 89 0c 18 90 02 ff 83 90 03 01 01 d2 c2 04 90 02 ff 83 90 03 01 01 d7 c7 04 90 00 } //01 00 
		$a_03_2 = {31 34 24 66 90 0a ff 00 ff 37 90 02 ff 59 90 02 ff 89 0c 18 90 02 ff 83 90 03 01 01 d2 c2 04 90 02 ff 83 90 03 01 01 d7 c7 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}