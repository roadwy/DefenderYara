
rule PWS_Win32_Fareit_SU_MTB{
	meta:
		description = "PWS:Win32/Fareit.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 41 41 41 41 [0-10] 83 c6 01 [0-05] 8b 17 [0-10] 31 f2 [0-10] 39 ca 75 } //1
		$a_03_1 = {b9 00 5f 00 00 [0-10] 49 [0-10] 8b 1c 0f [0-10] 53 [0-20] 31 34 24 [0-25] 8f 04 08 [0-15] 83 f9 00 7f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}