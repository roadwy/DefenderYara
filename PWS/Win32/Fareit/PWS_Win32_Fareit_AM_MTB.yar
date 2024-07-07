
rule PWS_Win32_Fareit_AM_MTB{
	meta:
		description = "PWS:Win32/Fareit.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1a 80 f3 90 01 01 8b f9 03 f8 73 05 90 02 0a 88 1f 90 02 20 40 42 3d 90 02 10 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}