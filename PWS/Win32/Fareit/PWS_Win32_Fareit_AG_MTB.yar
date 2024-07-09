
rule PWS_Win32_Fareit_AG_MTB{
	meta:
		description = "PWS:Win32/Fareit.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 34 08 81 [0-40] 81 34 24 [0-40] 8f 04 08 [0-40] 83 c1 04 } //1
		$a_03_1 = {ff 34 08 3d [0-40] 81 34 24 [0-40] 8f 04 08 [0-40] 83 c1 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}