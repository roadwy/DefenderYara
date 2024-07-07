
rule PWS_Win32_Fareit_DA_MTB{
	meta:
		description = "PWS:Win32/Fareit.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 41 41 41 41 90 02 10 46 90 02 10 8b 17 90 02 10 33 14 90 02 10 39 ca 75 90 00 } //20
		$a_03_1 = {b9 f0 5f 00 00 90 02 10 49 90 02 10 ff 34 0f 90 02 10 5b 90 02 10 31 f3 90 02 25 09 1c 08 90 02 10 83 f9 00 7f 90 00 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*5) >=25
 
}