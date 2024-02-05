
rule PWS_Win32_Fareit_MR_MTB{
	meta:
		description = "PWS:Win32/Fareit.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1a 80 f3 90 01 01 88 5d 90 02 06 8b 5d 90 01 01 8b fb 8a 5d 90 01 01 88 1f 90 02 04 83 c6 90 01 01 73 90 01 01 e8 90 02 0c 42 49 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}