
rule PWS_Win32_Fareit_I_MTB{
	meta:
		description = "PWS:Win32/Fareit.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 34 1f 52 81 f2 90 01 04 5a 68 90 01 04 68 90 00 } //01 00 
		$a_02_1 = {89 14 18 52 81 f2 90 01 04 5a 90 02 ff 83 c4 08 83 fb 00 0f 85 90 01 02 ff ff eb 90 00 } //01 00 
		$a_00_2 = {8b 54 24 04 } //01 00 
		$a_00_3 = {58 31 f2 68 } //00 00 
	condition:
		any of ($a_*)
 
}