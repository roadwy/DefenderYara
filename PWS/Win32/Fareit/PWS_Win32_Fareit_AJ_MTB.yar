
rule PWS_Win32_Fareit_AJ_MTB{
	meta:
		description = "PWS:Win32/Fareit.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {38 62 3c 0a 75 90 02 ff 81 f7 90 02 ff 31 3c 08 90 02 ff 49 90 02 40 49 90 02 40 49 90 02 40 49 90 00 } //01 00 
		$a_03_1 = {38 62 3c 0a eb 90 02 ff 81 f7 90 02 ff 31 3c 08 90 02 ff 49 90 02 40 49 90 02 40 49 90 02 40 49 90 00 } //01 00 
		$a_03_2 = {38 62 3c 0a 71 90 02 ff 81 f7 90 02 ff 31 3c 08 90 02 ff 49 90 02 40 49 90 02 40 49 90 02 40 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}