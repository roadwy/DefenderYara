
rule PWS_Win32_Fareit_JK_MTB{
	meta:
		description = "PWS:Win32/Fareit.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 e8 f9 fe 90 01 02 ba 90 01 04 b8 90 01 04 31 c9 80 34 01 fd 41 89 c9 39 d1 90 02 02 75 90 01 01 05 90 01 04 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}