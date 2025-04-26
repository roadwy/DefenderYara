
rule PWS_Win32_Fareit_MU_MTB{
	meta:
		description = "PWS:Win32/Fareit.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c6 03 c7 [0-01] a3 [0-06] 88 15 [0-05] 8b 0d [0-04] a0 [0-04] 88 01 [0-03] 47 81 ff [0-04] 75 90 09 12 00 8b c7 [0-04] 8a [0-05] 32 d3 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}