
rule PWS_Win32_Fareit_DA_MTB{
	meta:
		description = "PWS:Win32/Fareit.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 41 41 41 41 [0-10] 46 [0-10] 8b 17 [0-10] 33 14 [0-10] 39 ca 75 } //20
		$a_03_1 = {b9 f0 5f 00 00 [0-10] 49 [0-10] ff 34 0f [0-10] 5b [0-10] 31 f3 [0-25] 09 1c 08 [0-10] 83 f9 00 7f } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*5) >=25
 
}