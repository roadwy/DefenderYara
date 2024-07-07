
rule PWS_Win32_Fareit_Delph_AD{
	meta:
		description = "PWS:Win32/Fareit.Delph.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1a 80 f3 90 01 01 88 5d f7 90 05 05 01 90 8b 5d f8 8b fb 8a 5d f7 88 1f 90 02 30 03 4d fc ff d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}