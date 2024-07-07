
rule PWS_Win32_Fareit_AQ_MTB{
	meta:
		description = "PWS:Win32/Fareit.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 34 01 7e 90 02 40 41 90 02 50 39 d9 90 02 40 75 90 02 50 05 90 01 02 00 00 90 02 50 ff e1 90 00 } //1
		$a_03_1 = {89 c9 80 34 01 90 02 40 41 90 02 50 39 d9 90 02 40 75 90 02 50 05 90 01 02 00 00 90 02 50 ff e1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}