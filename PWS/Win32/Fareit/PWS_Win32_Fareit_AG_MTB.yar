
rule PWS_Win32_Fareit_AG_MTB{
	meta:
		description = "PWS:Win32/Fareit.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 34 08 81 90 02 40 81 34 24 90 02 40 8f 04 08 90 02 40 83 c1 04 90 00 } //01 00 
		$a_03_1 = {ff 34 08 3d 90 02 40 81 34 24 90 02 40 8f 04 08 90 02 40 83 c1 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}